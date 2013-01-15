# See bottom of file for license and copyright information
package Foswiki::Configure::Checkers::Plugins::SafeWikiPlugin::Enabled;
use warnings;
use strict;

use Foswiki::Configure::Checker;

use Foswiki::Configure::Checker;
our @ISA = qw( Foswiki::Configure::Checker );

sub check {
    my $this = shift;
    my $warnings;
    my $defaultUrlHost = $Foswiki::cfg{DefaultUrlHost};
    my $scriptUrlPath  = $Foswiki::cfg{ScriptUrlPath};
    my $viewUrlPath    = $Foswiki::cfg{ScriptUrlPaths}{view};

    if ( $Foswiki::cfg{Plugins}{SafeWikiPlugin}{Enabled} ) {
        if ( $Foswiki::cfg{INCLUDE}{AllowURLs} ) {
            $warnings .= $this->WARN(<<'HERE');
{INCLUDE}{AllowURLs} is true, which allows topic contributors to
<code>%INCLUDE%</code> content from arbitrary URLs.
HERE
        }
        if ( $Foswiki::cfg{AllowRedirectUrl} ) {
            $warnings .= $this->WARN(<<"HERE");
{AllowRedirectUrl} is true, giving more power to the 
<code>?redirectto</code> URL parameter than is usually necessary. For example, a 
specially crafted link may be used on some scripts to redirect a user to an 
arbitrary external URL after performing some action, <a href=
'$defaultUrlHost$scriptUrlPath/edit/Sandbox/TestTopicAUTOINC0?redirectto=http://www.w3.org'>
like this</a>.
HERE
        }
    }
    else {
        $warnings .= $this->WARN(<<"HERE");
Turning on SafeWikiPlugin is strongly recommended because without it,
Foswiki cannot reliably protect your users against cross-site scripting. See the
<a href="$defaultUrlHost$viewUrlPath/System/SafeWikiPlugin">plugin topic</a>
for more information.
HERE
    }

    return $warnings;
}

1;
__DATA__
#
# Foswiki - The Free and Open Source Wiki, http://foswiki.org/
#
# Copyright (C) 2009-2013 Foswiki Contributors. All Rights Reserved.
# Foswiki Contributors are listed in the AUTHORS file in the root
# of this distribution. NOTE: Please extend that file, not this notice.
#
# Additional copyrights apply to some or all of the code in this
# file as follows:
#
# Copyright (C) 2000-2006 TWiki Contributors. All Rights Reserved.
# TWiki Contributors are listed in the AUTHORS file in the root
# of this distribution. NOTE: Please extend that file, not this notice.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version. For
# more details read LICENSE in the root of this distribution.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# As per the GPL, removal of this notice is prohibited.
