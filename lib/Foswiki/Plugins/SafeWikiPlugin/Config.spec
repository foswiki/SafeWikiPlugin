#---+ Extensions
#---++ SafeWikiPlugin
# **SELECT FAIL,WARN**
# If set to FAIL, then threats will be defused. If set to WARN, then Foswiki
# will continue to operate normally and any threats are logged to the error
# log without being disarmed (this is useful when tuning the filters for
# a specific site).
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{Action} = 'FAIL';

# **BOOLEAN**
# If this option is enabled, then the plugin will check HTML for
# correctness. While nowhere near as rigorous as a full XHTML validation,
# this check will at least highlight malformed HTML that might be exploited
# by a hacker.
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{CheckPurity} = 0;

#---+++ Event Handlers
# **PERL**
# Array of perl regular expressions, one of which must match the value
# of an on* handler, or it will be filtered. The default permits a simple
# function call; for example:
# <tt>javascript: fn(param1, "param2")</tt>
# You can use other Foswiki::cfg variables in the the strings here.
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{SafeHandler} = [
          '^(\s*javascript:)?(\s*return)?\s*\w+\s*\(((\w+|\'[^\']*\'|"[^"]*")(\s*,\s*(\w+|\'[^\']*\'|"[^"]*"))*|\s*)?\)[\s;]*(return\s+(\w+|\'[^\']*\'|"[^"]*")[\s;]*)?$',
          '^StrikeOne\.submit\(this\);?(document\.loginform\.foswiki_origin\.value\+=window\.location\.hash)?$',
        ];

# **PERL**
# Array of perl regular expressions. If any of these match the value
# of an on* handler, it will be filtered. The default exludes use of
# 'eval' calls.
# You can use other Foswiki::cfg variables in the the strings here.
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{UnsafeHandler} = ['\beval\s*\('];

# **STRING 30**
# String used to replace dodgy handlers.
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{DisarmHandler} = 'alert("Handler filtered by SafeWikiPlugin")';

#---+++ URIs
# **PERL**
# HTML tags and attributes that will be URI-filtered by the SafeWikiPlugin.
# These attributes are filtered if the tag is included in {Plugins}{SafeWikiPlugin}{FilterTags}
# and the attributes value matches any expression in
# {Plugins}{SafeWikiPlugin}{UnsafeURI} or fails to match at least one expression
# in {Plugins}{SafeWikiPlugin}{SafeURI} (if any are defined). The following quick reference lists
# all the URI attributes on all HTML4 & HTML5 tags, should you want to include any of them.
# <pre>
# A          => [ 'href' ],
# APPLET     => [ 'archive', 'code', 'codebase' ],
# AREA       => [ 'href' ],
# AUDIO      => [ 'src' ],
# BASE       => [ 'href' ],
# BLOCKQUOTE => [ 'cite' ],
# BODY       => [ 'background' ],
# BUTTON     => [ 'formaction' ],
# DEL        => [ 'cite' ],
# EMBED      => [ 'pluginspace', 'pluginurl', 'href', 'target', 'src' ],
# FORM       => [ 'action' ],
# FRAME      => [ 'src', 'longdesc' ],
# IFRAME     => [ 'src', 'longdesc' ],
# IMG        => [ 'src', 'longdesc', 'usemap' ],
# INPUT      => [ 'src', 'usemap' ],
# INS        => [ 'cite' ],
# LINK       => [ 'href' ],
# OBJECT     => [ 'archive', 'codebase', 'data', 'usemap' ],
# Q          => [ 'cite' ],
# SCRIPT     => [ 'src' ],
# SOURCE     => [ 'src' ],
# VIDEO      => [ 'src', 'poster' ]
# </pre>
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{Tags} = {
    APPLET     => [ 'archive', 'code', 'codebase' ],
    EMBED      => [ 'pluginspace', 'pluginurl', 'src' ],
    OBJECT     => [ 'archive', 'codebase' ],
    SCRIPT     => [ 'src' ]
};

# **PERL**
# Array of perl regular expressions, one of which must be matched for
# a URI used in a Foswiki page to be passed unfiltered. You can
# use other Foswiki::cfg variables in the the strings here.
# Note that you will have to extend this list if you have used
# <code>{PermittedRedirectHostUrls}</code> in your configuration.
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{SafeURI} = ['^(|http://(localhost|127\.0\.0\.1)(:\d*)?|$Foswiki::cfg{DefaultUrlHost})/*$Foswiki::cfg{PubUrlPath}/+$Foswiki::cfg{SystemWebName}/+'];

# **PERL**
# Array of perl regular expressions. If any of these match
# a URI used in a Foswiki page it will be filtered.
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{UnsafeURI} = [];

# **STRING 30**
# String used to replace dodgy URIs. Can be a URI if you want.
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{DisarmURI} = 'URI filtered by SafeWikiPlugin';

#---+++ SCRIPT tags
# **PERL**
# Array of perl regular expressions, one of which must match the contents
# of an inline script tag or it will be filtered. The default permits a simple
# Allows the TinyMCEPlugin to provide its inline init code.
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{SafeInline} = [
          '^\s?FoswikiTiny\.init.*'
        ];

