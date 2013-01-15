# See bottom of file for license and copyright information
package Foswiki::Configure::Checkers::Plugins::SafeWikiPlugin::SecretKey;
use warnings;
use strict;

use Foswiki::Configure::Checker;

use Foswiki::Configure::Checker;
our @ISA = qw( Foswiki::Configure::Checker );

sub check {
    my $this = shift;

    return unless $Foswiki::cfg{Plugins}{SafeWikiPlugin}{Enabled};
    if ( $Foswiki::cfg{Plugins}{SafeWikiPlugin}{SecretKey} eq
        'this is a bad key' )
    {
        return $this->WARN(<<"HERE");
{Plugins}{SafeWikiPlugin}{SecretKey} is set to the default value. In other
words, your SafeWikiPlugin is wide open and it's a really, really good idea
to set a secure key instead.
HERE
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
of the License, or (at your option) any later version. For
more details read LICENSE in the root of this distribution.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

As per the GPL, removal of this notice is prohibited.
