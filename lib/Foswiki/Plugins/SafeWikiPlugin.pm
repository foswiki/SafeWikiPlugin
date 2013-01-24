# See bottom of file for notices
package Foswiki::Plugins::SafeWikiPlugin;

use strict;
use Assert;
use Error ':try';
use Digest::SHA qw(sha256_base64);
use Digest::HMAC_SHA1;

use Foswiki::Meta ();
use Foswiki::Macros::ADDTOZONE;
use Foswiki::Plugins::SafeWikiPlugin::Signatures ();
use Foswiki::Plugins::SafeWikiPlugin::Parser     ();
use Foswiki::Plugins::SafeWikiPlugin::CoreHooks  ();
use Foswiki::Sandbox                             ();

our $VERSION = '$Rev$';
our $RELEASE = '2.0.0';
our $SHORTDESCRIPTION =
  'Secure your Foswiki so it can\'t be used for mounting phishing attacks';
our $NO_PREFS_IN_TOPIC = 1;

our %FILTERIN;
our %FILTEROUT;
our $parser;
our %STRIP_TAGS;

sub earlyInitPlugin {
    return if !$Foswiki::cfg{Plugins}{SafeWikiPlugin}{Enabled};
    Foswiki::Plugins::SafeWikiPlugin::CoreHooks::hook();
    Foswiki::Func::getContext()->{SafeWikiSignable} = 1;
    return undef;
}

sub initPlugin {
    unless ($parser) {
        $parser = new Foswiki::Plugins::SafeWikiPlugin::Parser();
    }

    $Foswiki::cfg{Plugins}{SafeWikiPlugin}{Action} ||= 'FAIL';
    Foswiki::Plugins::SafeWikiPlugin::Signatures::read();

    my $strip_tags = $Foswiki::cfg{Plugins}{SafeWikiPlugin}{StripTags}
      || "FRAME,IFRAME";
    foreach my $tag ( split( /\s*,\s*/, $strip_tags ) ) {
        $STRIP_TAGS{ uc($tag) } = 1;
    }

    return $parser ? 1 : 0;
}

my $CONDITIONAL_IF    = "<!--C\0NDITI\0N-->";
my $CONDITIONAL_ENDIF = "<!--COND\1T\1ON-->";

# Handle the complete HTML page about to be sent to the browser
sub completePageHandler {

    #my($html, $httpHeaders) = @_;

    return unless $_[1] =~ m#^Content-type: text/html#mi;

    # PDF generation fails if we filter it, so don't do that
    if ( exists $Foswiki::cfg{Plugins}{GenPDFPrincePlugin}{Enabled}
        && $Foswiki::cfg{Plugins}{GenPDFPrincePlugin}{Enabled} )
    {
        my $query = Foswiki::Func::getCgiQuery();
        my $contenttype = $query->param("contenttype") || 'text/html';
        return if $contenttype eq 'application/pdf';
    }

   # Some ajax requests fetch text without being wrapped in <html>..</html>
   # It results in a parser error: Unexpected leaf: 0:  If the tags are missing,
   # wrap text in <html> tags so that the parser will function on html segments
    my $insertHtml = 0;
    unless ( $_[0] =~ m/<html\b/ ) {
        $insertHtml = 1;
        $_[0] = '<html>' . $_[0] . '</html>';
    }

    my @condifs;

    #<!--[if IE]><style type="text/css" media="screen">
    #pre {
    #	overflow-x:auto;
    #}
    #</style>
    #<![endif]-->

    # Parse the HTML and generate a parse tree
    # This handler can be patched into pre-4.2 revs of Foswiki
    $_[0] =~ s/(<!--\[if [^]]*\]>)(.*?)<!\[endif\]-->/
      push(@condifs, $1);
      "${CONDITIONAL_IF}$#condifs;$2$CONDITIONAL_ENDIF"/ges;

    my $holdHTML = $_[0];
    eval {
        $parser->parseHTML( $_[0] );
        $_[0] =
          $parser->generate( \&_filterURI, \&_filterHandler, \&_filterInline );
    };
    if ($@) {
        if ( $Foswiki::cfg{Plugins}{SafeWikiPlugin}{Action} eq 'WARN' ) {
            print STDERR "SAFEWIKI: exception while processing\n $@\n";
            $_[0] = $holdHTML;
        }
        else {
            my $e = $@;
            $_[0] = Foswiki::Func::loadTemplate('safewikierror')
              || "Error loading safewiki error page. %EXCEPTION%";
            $_[0] =~ s/%EXCEPTION%/$e/;
            ASSERT( 0, "SAFEWIKI: FAIL $e" )
              if DEBUG
              && $Foswiki::cfg{Plugins}{SafeWikiPlugin}{Action} eq 'ASSERT';
        }
    }

    $_[0] =~
s/${CONDITIONAL_IF}(\d+);(.*?)$CONDITIONAL_ENDIF/$condifs[$1]$2<![endif]-->/gs;

    # Bring back the zones... we miss them terribly
    my $session = $Foswiki::Plugins::SESSION;
    my $topicObject =
      Foswiki::Meta->load( $session, $session->{webName},
        $session->{topicName} );
    Foswiki::Plugins::SafeWikiPlugin::Signatures::unhoist( $_[0],
        $topicObject );

    # unwrap the text if we inserted the <html> tags.
    if ($insertHtml) {
        $_[0] =~ s/^<html>//;
        $_[0] =~ s/<\/html>$//;
    }
}

sub _filter {
    my ( $code, $type ) = @_;

    unless ( $type eq 'URI' ) {
        return 1
          if Foswiki::Plugins::SafeWikiPlugin::Signatures::trustedInlineCode(
            $code);
    }

    if ( scalar( $Foswiki::cfg{Plugins}{SafeWikiPlugin}{"Safe$type"} || '' ) ) {
        unless ( defined( $FILTERIN{$type} ) ) {

            # the eval expands $Foswiki::cfg vars
            $FILTERIN{$type} = join( '|',
                map { s/(\$Foswiki::cfg({.*?})+)/eval($1)/ge; qr/($_)/ }
                  @{ $Foswiki::cfg{Plugins}{SafeWikiPlugin}{"Safe$type"} } );
        }
        return 0 unless ( $code =~ /$FILTERIN{$type}/ );
    }
    return 1;
}

# Something was disarmed; either warn or error out. If DEBUG is enabled,
# raise an ASSERT.
sub _report {
    my ( $m, $code ) = @_;
    $m =
        "SafeWikiPlugin: $Foswiki::cfg{Plugins}{SafeWikiPlugin}{Action}: "
      . $m . " on "
      . ( $ENV{REQUEST_URI}  || 'command line' )
      . ( $ENV{QUERY_STRING} || '' );
    if ( DEBUG && $Foswiki::cfg{Plugins}{SafeWikiPlugin}{Action} eq 'ASSERT' ) {
        ASSERT( 0,
                $m
              . " (SHA: "
              . Foswiki::Plugins::SafeWikiPlugin::Signatures::getSHA($code)
              . ", MAC: "
              . Foswiki::Plugins::SafeWikiPlugin::Signatures::getMAC($code)
              . ") $code" );
    }
    $m .= "\n$code";
    Foswiki::Func::writeWarning($m);
    return $Foswiki::cfg{Plugins}{SafeWikiPlugin}{Action} eq 'WARN';
}

sub _filterInline {
    my $code = shift;
    return '' unless defined $code && length($code);
    return $code if _filter( $code, 'Inline' );
    return $code if _report( "Disarmed inline", $code );
    $code =~ s#/\*#/+#gs;
    $code =~ s#\*/#+/#gs;
    return "/* Inline code disarmed by SafeWikiPlugin: $code */";
}

sub _filterURI {
    my $uri = shift;

    return $uri if _filter( $uri, 'URI' );
    return $uri if _report( "Disarmed URI", $uri );
    return $Foswiki::cfg{Plugins}{SafeWikiPlugin}{DisarmURI}
      || 'URI filtered by SafeWikiPlugin';
}

sub _filterHandler {
    my $code = shift;
    return '' unless defined $code && length($code);
    my $type = shift || "on*";
    return $code if _filter( $code, 'Handler' );
    return $code if _report( "Disarmed $type", $code );
    my $res = $Foswiki::cfg{Plugins}{SafeWikiPlugin}{DisarmHandler}
      || '/*Code removed by SafeWikiPlugin*/';

    # Once more, special treatment for the all-important StrikeOne
    if ( $code =~ /^StrikeOne\.submit\(this\);?/ ) {
        $res = "StrikeOne\.submit\(this\);$res";
    }
    return $res;

}

1;
__DATA__

Copyright (C) 2007-2009 C-Dot Consultants http://c-dot.co.uk
Copyright (C) 2013 Modell Aachen GmbH http://modell-aachen.de
All rights reserved
Authors: Crawford Currie, Jan Krueger

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
