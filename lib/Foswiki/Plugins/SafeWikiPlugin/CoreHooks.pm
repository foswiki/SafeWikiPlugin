# See bottom of file for notices

package Foswiki::Plugins::SafeWikiPlugin::CoreHooks;

use strict;
use warnings;
use Assert;
use Foswiki::Plugins::SafeWikiPlugin::Signatures ();
use Foswiki::Render::Zones;

my $hooked;
my ( $oldADDTOZONE, $oldaddToZone );    # is this confusing?
my $ATZsig;    # hack to let addToZone know we're calling it from the ATZ macro

sub hook {
    # Prevent nasties on FastCGI/mod_perl
    # If the hooks were applied twice, the $old... variables would end up
    # containing the hooks themselves and we'd get ourselves stuck in an
    # infinite loop...
    return if defined $hooked;

    # Overwrite the normal Foswiki functions for adding zones.
    # This is, sadly, necessary if we want to have the ability to
    # magically let through all zone code added directly by plugins
    # (e.g. JQueryPlugin's prefs object).
    $oldADDTOZONE = \&Foswiki::ADDTOZONE;
    $oldaddToZone = \&Foswiki::Render::Zones::addToZone;

    undef *Foswiki::ADDTOZONE;
    undef *Foswiki::Render::Zones::addToZone;

    *Foswiki::ADDTOZONE =
      \&Foswiki::Plugins::SafeWikiPlugin::CoreHooks::ADDTOZONE;
    *Foswiki::Render::Zones::addToZone =
      \&Foswiki::Plugins::SafeWikiPlugin::CoreHooks::addToZone;

    $hooked = 1;
    return;
}

sub ADDTOZONE {
    my ( $this, $params, $topicObject ) = @_;
    $ATZsig = $params->{signature};
    $ATZsig = '' if !defined $params->{signature};

    my $res = $oldADDTOZONE->(@_);

    undef $ATZsig;
    return $res;
}

sub addToZone {
    my ( $this, $zone, $id, $data, $requires, $signature ) = @_;

    # Are we being called from ADDTOZONE? Patch in the signature we actually
    # received in the macro
    # This is perhaps slightly cleaner than copypasta-ing ADDTOZONE
    $signature = $ATZsig if defined $ATZsig;

    # the original code limits this to 10k; might as well reduce the chance
    # of conflicts while we are forced to re-implement this (we need to know
    # the ID and we can't get at it if it was generated during the original
    # addToZone call)
    unless ($id) {
        $id = int( rand(1_000_000_000) );
    }

    $oldaddToZone->( $this, $zone, $id, $data, $requires, $signature );
    my $zoneID = $this->{_zones}{$zone}{$id};

    Foswiki::Plugins::SafeWikiPlugin::Signatures::processZone( $zoneID,
        $signature );

    return;
}

1;
__DATA__

Foswiki - The Free and Open Source Wiki, http://foswiki.org/

Copyright (C) 2008-2013 Foswiki Contributors. Foswiki Contributors
are listed in the AUTHORS file in the root of this distribution.
NOTE: Please extend that file, not this notice.

Additional copyrights may apply to some or all of the code in this
file as follows:

Copyright (C) 2013 Modell Aachen GmbH, http://modell-aachen.de
Author: Jan Krueger

Copyright (C) 1999-2007 Peter Thoeny, peter@thoeny.org
and TWiki Contributors. All Rights Reserved. TWiki Contributors
are listed in the AUTHORS file in the root of this distribution.
Based on parts of Ward Cunninghams original Wiki and JosWiki.
Copyright (C) 1998 Markus Peter - SPiN GmbH (warpi@spin.de)
Some changes by Dave Harris (drh@bhresearch.co.uk) incorporated

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version. For
more details read LICENSE in the root of this distribution.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

As per the GPL, removal of this notice is prohibited.
