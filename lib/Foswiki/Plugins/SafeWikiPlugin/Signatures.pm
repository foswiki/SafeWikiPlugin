# See bottom of file for notices
package Foswiki::Plugins::SafeWikiPlugin::Signatures;

use strict;
use Digest::SHA qw(sha256_base64);
use Digest::HMAC_SHA1;

use Assert;
use Foswiki::Sandbox ();

our %SIGNATURES;
our %TMP_SIGNATURES;
my $signatures_inited;
our %HOISTED_CODE;

# Macros we'll automatically let through while unhoisting (see below)
our @SAFE_EXPAND = (
    [
        'identifier', qr/\$percnt(?:
        (?:BASE|INCLUDING|)(?:WEB|TOPIC)|
        (?:MAIN|SYSTEM|TWIKI|USERS)WEB|
        HOMETOPIC|LANGUAGE|WEBPREFSTOPIC
    )\$percnt/x
    ],
    [
        'string', qr/\$percnt(?:
        SCRIPTURL(?:PATH)?\{\w+\}|
        (?:ATTACH|PUB)URL(?:PATH)?|
        MAKETEXT\{"(?:[^\\"]+)"\}|MAKETEXT\{(?:[^\\"}]+)\}|
        NOTIFYTOPIC|QUERYSTRING|REMOTE_ADDR|REMOTE_PORT|REMOTE_USER|SCRIPTNAME|SCRIPTSUFFIX|SESSIONID|TOPICURL|
        URLPARAM\{\w+\}|URLPARAM\{"[^\\"]+"\}|
        USERNAME|WIKIHOMEURL|WIKINAME|WIKIPREFSTOPIC|WIKITOOLNAME|WIKIUSERNAME|WIKIUSERSTOPIC|WIKIVERSION|
        WIKIWEBMASTER|WIKIWEBMASTERNAME
    )\$percnt/x
    ],
);

my ( $key, $mac, $requestId );

sub init {
    $requestId = sprintf( "%09d", rand 1_000_000_000 );
}
init() unless defined $requestId;

# Read signatures from standard places (LSC, Signatures subdir)
sub read {
    return if $signatures_inited;
    $signatures_inited = 1;

    _addSHA( @{ $Foswiki::cfg{Plugins}{SafeWikiPlugin}{SignaturesList} } );

    my $sigsdir =
      $Foswiki::foswikiLibPath . "/Foswiki/Plugins/SafeWikiPlugin/Signatures";
    {    # "loop" to break out of with 'last'
        my $dirh;
        opendir( $dirh, $sigsdir ) or do {
            Foswiki::Func::writeWarning(
"Can't access $sigsdir ($!); some system JavaScript may break because of this"
            );
            last;
        };
        foreach my $sigfile ( readdir($dirh) ) {
            next if ( $sigfile !~ /\.pm$/ );

            # Explicit untaint ok -- no user input in here
            my $sigsfilepath =
              Foswiki::Sandbox::untaintUnchecked("$sigsdir/$sigfile");
            my $sigs = do $sigsfilepath;
            unless ( defined $sigs ) {
                my $err = defined($@) ? $@ : $!;
                Foswiki::Func::writeWarning(
"Problem reading $sigsfilepath ($err); some system JavaScript may break because of this"
                );
            }
            _addSHA( @{$sigs} );
        }
    }
    if ( $Foswiki::cfg{Plugins}{SafeWikiPlugin}{SignaturesTopic} ) {
        my ( $sigWeb, $sigTopic ) =
          Foswiki::Func::normalizeWebTopicName( '',
            $Foswiki::cfg{Plugins}{SafeWikiPlugin}{SignaturesTopic} );
        my ( $meta, $text ) = Foswiki::Func::readTopic( $sigWeb, $sigTopic );
        if ($text) {
            $text =~ s/^\|\s?(.*?)\s?\|/_addSHA($1)/msge;
        }
    }
}

# Used by our addToZone hook; sets aside the content of zones with trusted
# contents. It does this by substituting a placeholder; the 'unhoist' function
# below reverses that.
sub processZone {
    my ( $zone, $signature ) = @_;
    my $data    = $zone->{text};
    my $realMAC = getMAC($data);

    # undef = default when calling addToZone from plugins. Plugins are
    # trustworthy. %ADDTOZONE% passes empty string instead.\
    # Therefore, undef = trusted.
    goto TRUST if !defined $signature;

    goto TRUST if $signature eq $realMAC;

    # Only calculate SHA as a last resort
    my $realSHA = getSHA($data);
    goto TRUST if _haveSHA($realSHA);

    # We really tried trusting but we couldn't do it :(
    print STDERR
"SafeWikiPlugin: SHA $realSHA MAC $realMAC for this zone content: $data\n\n---\n"
      if DEBUG && $signature ne '';
    return;

    # lift out this block and put it back later
  TRUST: {
        $HOISTED_CODE{$realMAC} = $data;
        $zone->{text} = "<!--safewiki:$realMAC-->";
    }
}

# Re-insert zone contents removed from the page earlier (by 'processZone'
# above). Also allow embedded escaped macros to expand at this point, but only
# if they are explicitly validated.
# For more information about the validation, see the plugin topic
# (System.SafeWikiPlugin).
sub unhoist {
    my $topicObject = pop;
    my $unhoist     = sub {
        my $sig = shift;
        if ( !exists $HOISTED_CODE{$sig} ) {
            Foswiki::Func::writeWarning(
                "Attempt to unhoist unknown signed code: $sig");
            return '';
        }

        # Unescape and expand macros if they are successfully validated
        my @safe_macros = @SAFE_EXPAND;
        my $code        = $HOISTED_CODE{$sig};

        # Expand unescaped macros
        # These can only really exist at this point if the zone entry was
        # added by a plugin (which is relying on automatic expansion by the
        # core).
        # In all other cases, unescaped macros will all have been expanded
        # at this point
        $code = $topicObject->expandMacros($code);

        # Fetch list of validated macros from inline code
        # We need to *prepend* the inline validators because otherwise the stock
        # ones will run before these and possibly mangle nested macros
        $code =~ s#/\*safewiki:(string|identifier)\*/
            (["']?)(.+?)(\2)
            /\*safewiki:end\*/\s*
            #unshift @safe_macros, [$1, qr/\Q$3\E/]; $2.$3.$4#egx;
        foreach my $m (@safe_macros) {
            $code =~ s/(["']?)($m->[1])(\1)/
                $1 . _safeExpand($2, $m->[0], $1, $topicObject) . $1
            /eg;
        }
        return $code;
    };

    # Work in order of appearance, just in case the order of macro expansion
    # matters
    $_[0] =~ s/<!--safewiki:([0-9A-Za-z\/\+]{27})-->/$unhoist->($1)/eg;

    # For the sake of FastCGI, regenerate a new 'request ID' at this time.
    # At this point we're done messing with zones, so this won't have any
    # effect on the current request.
    init();

    # Similarly we can get rid of temporary signatures now.
    %TMP_SIGNATURES = ();
}

# Determine HMAC signature for a given piece of code
sub getMAC {
    my $text = shift;
    my $key  = $Foswiki::cfg{Plugins}{SafeWikiPlugin}{SecretKey};
    my $mac  = Digest::HMAC_SHA1->new($key);
    $mac->add($text);
    return $mac->b64digest;
}

# Simple: hash a piece of code
sub getSHA { return sha256_base64(shift); }

# Check if we have the signature for a piece of code in our whitelist
sub checkSHA { return _haveSHA( getSHA(shift) ); }

# Given a piece of inline JavaScript code, check that it's either authorized
# via a SHA256 signature provided by a plugin/admin, or via an inline HMAC
# signature.
sub trustedInlineCode {
    my $code  = shift;
    my $ccode = _canonicalizedCode($code);
    return 1 if checkSHA($ccode);

    $code =~ m#^\s*/\*safewiki:([0-9a-zA-Z+/]{27})\*/#;
    return 1 if ( $1 && getMAC($ccode) eq $1 );
    return 0;
}

# Make sure that the given piece of inline JavaScript code (handler or
# <script> tag) will be accepted during the current request.
sub permitInlineCode {
    my $sha = getSHA( _canonicalizedCode(shift) );
    $TMP_SIGNATURES{$sha} = 1;
}

sub _addSHA {
    foreach my $sha (@_) {
        $SIGNATURES{$sha} = 1 if length($sha) eq 43;    # basic sanity check
    }
}

sub _haveSHA {
    return exists $SIGNATURES{ $_[0] } || exists $TMP_SIGNATURES{ $_[0] };
}

# Generates a canonicalized form of inline code that gets the same signature
# even if it gets mangled a little bit
# In particular, this removes any inline signature first (duh, we can't sign
# the signature with itself)
sub _canonicalizedCode {
    my $text = shift;
    $text =~ s/\s+/ /g;
    $text =~ s/(^\s+|\s+$)//g;
    $text =~ s#^\s*/\*safewiki:[0-9A-Za-z+/]{27}\*/\s*##;
    return $text;
}

# Work horse for expanding validated macros in code during unhoisting
sub _safeExpand {
    my ( $macro, $type, $quote, $topicObject ) = @_;
    my $unescMacro = Foswiki::expandStandardEscapes($macro);
    my $exp =
      $topicObject->expandMacros( Foswiki::expandStandardEscapes($unescMacro) );
    $type = lc($type);

    if ( $type eq 'string' ) {
        goto BADEXP if $exp =~ /[$quote\\]/;
    }
    elsif ( $type eq 'identifier' ) {
        goto BADEXP if $exp =~ /[^a-zA-Z0-9_]/;
    }
    return $exp;

  BADEXP: {
        $exp =~ s/\r*\n/\\n/g;
        print STDERR "/*safewiki:$type*/ not fulfilled here: $macro -> $exp\n";
    }
}

1;
__DATA__

Copyright (C) 2013 Modell Aachen GmbH http://modell-aachen.de
All rights reserved
Authors: Jan Krueger

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details, published at
http://www.gnu.org/copyleft/gpl.html

This notice must be retained in all copies or derivatives of this
code.

