# See bottom of file for notices

=pod

---+ package Foswiki::Plugins::SafeWikiPlugin::Node

A tree node in an HTML parse tree

=cut

package Foswiki::Plugins::SafeWikiPlugin::Node;

use strict;
use Assert;
use Encode;
use Foswiki::Func ();
use HTML::Entities;

# This is horribly misformatted because the perltidy is forcing me to
# do it this way.
my %uriTags = (
    A          => ['href'],
    APPLET     => [ 'archive', 'code', 'codebase' ],
    AREA       => ['href'],
    AUDIO      => ['src'],
    BASE       => ['href'],
    BLOCKQUOTE => ['cite'],
    BODY       => ['background'],
    BUTTON     => ['formaction'],
    DEL        => ['cite'],
    EMBED      => [ 'pluginspace', 'pluginurl', 'href', 'target', 'src' ],
    FORM       => ['action'],
    FRAME  => [ 'src', 'longdesc' ],
    IFRAME => [ 'src', 'longdesc' ],
    IMG    => [ 'src', 'longdesc', 'usemap' ],
    INPUT  => [ 'src', 'usemap' ],
    INS    => ['cite'],
    LINK   => ['href'],
    OBJECT => [ 'archive', 'codebase', 'data', 'usemap' ],
    Q      => ['cite'],
    SCRIPT => ['src'],
    SOURCE => ['src'],
    VIDEO => [ 'src', 'poster' ]
);

sub new {
    my ( $class, $tag, $attrs ) = @_;

    my $this = {};

    $this->{tag}   = lc($tag);
    $this->{attrs} = {};
    if ($attrs) {
        while ( my ( $k, $v ) = each %$attrs ) {
            $this->{attrs}->{$k} = $v;
        }
    }
    $this->{children} = [];

    return bless( $this, $class );
}

# debug generate the parse tree as HTML
sub stringify {
    my ( $this, $shallow ) = @_;
    my $r = '';
    if ( $this->{tag} ) {
        $r .= '<' . $this->{tag};
        foreach my $attr ( keys %{ $this->{attrs} } ) {
            if ( $attr =~ /^\w+$/ ) {
                $r .= " " . $attr . "='" . $this->{attrs}->{$attr} . "'";
            }
        }
        $r .= '>';
    }
    if ($shallow) {
        $r .= '...';
    }
    else {
        foreach my $kid ( @{ $this->{children} } ) {
            $r .= $kid->stringify();
        }
    }
    if ( $this->{tag} ) {
        $r .= '</' . lc( $this->{tag} ) . '>';
    }
    return $r;
}

sub isLeaf {
    return 0;
}

# Called by the parser
sub addChild {
    my ( $this, $node ) = @_;
    push( @{ $this->{children} }, $node );
}

# generate the parse tree, applying filters
sub generate {
    my ( $this, $filterURI, $filterHandler, $filterInline ) = @_;
    my $tag = $this->{tag};

    # make the names of the function versions
    my $f = uc($tag);
    $f =~ s/[^\w]//;    # clean up !DOCTYPE etc

    # Strip tag if it's on our list of baddies
    if ( exists $Foswiki::Plugins::SafeWikiPlugin::STRIP_TAGS{$f} ) {
        return '';
    }

    # See if we have a simple attributes filter for this tag
    $this->_filterURIs( $f, $filterURI, $filterHandler );

    # See if we have a tag-specific function for this tag type
    $f = "_$f";
    if ( $this->can($f) ) {

        # if the fn returns false, filter the entire tag and all children
        return '' unless $this->$f($filterURI);
    }

    # Unconditionally filter the handlers from all tags
    $this->_filterHandlers($filterHandler);

    # Process children
    my $text = '';
    foreach my $kid ( @{ $this->{children} } ) {
        $text .= $kid->generate( $filterURI, $filterHandler, $filterInline );
    }

    # Rebuild the tag parameters
    my @params;
    while ( my ( $k, $v ) = each %{ $this->{attrs} } ) {
        next unless $k && $k =~ /^(?:\w|-)+$/;

        # Attributes were not entity-decoded during parsing, to make c&p
        # signing easier. So we need to do a round trip. Yay!
        $v = encode_entities( decode_entities($v), '<>&"' );

        # This lovely hack courtesy of <nop> apparently being treated after
        # completePageHandler
        $v =~ s/&lt;(nop|\/?noautolink)&gt;/<$1>/g;

        push( @params, $k . "=\"$v\"" );
    }
    my $p = join( ' ', @params );
    $p = ' ' . $p if $p;

    if ( $tag =~ m/^script$/ && $text ) {
        my $holdtext = $text;
        $text = &$filterInline($text);
        return '' unless ($text);
    }

    # Rebuild the tag
    if ( $text eq '' && $tag =~ /^(p|br|img|hr|input|meta|link)$/i ) {
        return "<$tag$p />";
    }
    else {
        return "<$tag$p>$text</$tag>";
    }
}

# remove the event handlers named in the parameters from the tag
sub _filterHandlers {
    my ( $this, $filter ) = @_;

    foreach my $attr ( keys %{ $this->{attrs} } ) {
        my $value = $this->{attrs}{$attr};

        # Try to filter JQueryPlugin::METADATA's stuff, too
        if ( ( $attr eq 'class' || $attr eq 'data' ) && $value =~ /({.*})/ ) {
            my $code = $1;

            # Try to detect and allow simple objects
            # Sub-regex for a number, identifier or string
            # (doesn't accept all strings; we'd need real parsing for that)
            # in particular, strings may not contain escaped characters
            my $regexConstant = qr/(\w+|'[^'\\]*'|"[^"\\]*")/;
            my $regexListOrSingle =
qr/$regexConstant|\[\s*(?:$regexConstant(?:\s*,\s*$regexConstant)*)?\s*\]/;

            # Sub-regex for a key:value pair
            my $regexKVpair = qr/\s* $regexConstant \s* : \s* # key
                $regexListOrSingle \s* # array or simple value
            /x;
            next if $code =~ /^{(
            | # empty obj
            $regexKVpair(,$regexKVpair)* # arbitrary number of values
            )}$/x;

            # Otherwise, filter it
            $code = &$filter( $code, "metadata-via-class" );

            # Retain the obj syntax for JQP::METADATA
            $code = "{'dummy': [$code]}" unless $code =~ /^{.*}$/;
            $this->{attrs}{$attr} =~ s/{.*}/$code/;
            next;
        }

        # ... and the normal handler attributes, of course
        next unless $attr =~ /^on[a-z]+$/i;
        $this->{attrs}->{$attr} = &$filter( $this->{attrs}->{$attr} );
        ASSERT( defined $this->{attrs}->{$attr} ) if DEBUG;
    }

}

sub _filterURIs {
    my ( $this, $tag, $filter, $filterHandler ) = @_;

    # Unconditionally filter javascript: links
    if ( exists $uriTags{$tag} ) {
        foreach my $attr ( @{ $uriTags{$tag} } ) {
            if ( defined( $this->{attrs}{$attr} ) ) {
                next if ( $this->{attrs}{$attr} !~ /^\s*javascript:(.*)$/i );
                my $code = &$filterHandler($1);
                $this->{attrs}{$attr} = "javascript:$code";
            }
        }
    }

    # Filter according to config
    if ( exists $Foswiki::cfg{Plugins}{SafeWikiPlugin}{URIAttributes}{$tag} ) {
        foreach my $attr (
            @{ $Foswiki::cfg{Plugins}{SafeWikiPlugin}{URIAttributes}{$tag} } )
        {
            if ( defined( $this->{attrs}->{$attr} ) ) {
                $this->{attrs}->{$attr} = &$filter( $this->{attrs}->{$attr} );
                ASSERT( defined $this->{attrs}->{$attr} ) if DEBUG;
            }
        }
    }
}

# The following functions are each called when the tag with the same name
# is being generated. If the function returns 0, the tag is completely
# removed. Tags where we just want to filter the URI-valued
# attributes of the tags can be added to $filterAttrs; these functions
# are for "special cases" e.g. rewriting FORM action methods to always
# use POST (commented out below to serve as an example).

#sub _FORM {
#    my ($this) = @_;
#    $this->{attrs}->{method} = 'POST';
#    return 1;
#}

1;
__DATA__

Copyright (C) 2007-2009 C-Dot Consultants http://c-dot.co.uk
All rights reserved
Author: Crawford Currie

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
