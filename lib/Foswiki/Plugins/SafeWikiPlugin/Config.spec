#---+ Extensions
#---++ SafeWikiPlugin
# **SELECT WARN,FAIL**
# If set to WARN, then Foswiki will continue to operate normally and any threats
# are logged to the error log without being disarmed.
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{Action} = 'WARN';

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
# Array of perl regular expressions, one of which must match the contents
# of an inline script tag or it will be filtered. The default permits a simple
# Allows the TinyMCEPlugin to provide its inline init code.
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{SafeInline} = [
          '^\s?FoswikiTiny\.init.*'
        ];

# **PERL**
# Array of perl regular expressions. If any of these match the value
# of an on* handler, it will be filtered. The default exludes use of
# 'eval' calls.
# You can use other Foswiki::cfg variables in the the strings here.
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{UnsafeHandler} = ['\beval\s*\('];

# **STRING 30**
# String used to replace dodgy handlers and scripts.
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{DisarmHandler} = 'alert("Handler filtered by SafeWikiPlugin")';

# **PERL**
# Array of perl regular expressions, one of which must be matched for
# a URI used in a Foswiki page to be passed unfiltered. You can
# use other Foswiki::cfg variables in the the strings here.
# Note that you will have to extend this list if you have used
# <code>{PermittedRedirectHostUrls}</code>
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{SafeURI} = ['^(|http://(localhost|127\.0\.0\.1)(:\d*)?|$Foswiki::cfg{DefaultUrlHost})/*$Foswiki::cfg{PubUrlPath}/+$Foswiki::cfg{SystemWebName}/+'];

# **PERL**
# Array of perl regular expressions. If any of these match
# a URI used in a Foswiki page it will be filtered. You can
# use other Foswiki::cfg variables in the the strings here.
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{UnsafeURI} = [];

# **STRING 30**
# String used to replace dodgy URIs. Can be a URI if you want.
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{DisarmURI} = 'URI filtered by SafeWikiPlugin';

# **BOOLEAN**
# If this is option is enabled, then the plugin will filter *all* URIs, and not
# just those used in SCRIPT tags.
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{FilterAll} = 0;

# **BOOLEAN**
# If this is option is enabled, then the plugin will check HTML for
# correctness. While nowhere near as rigorous as a full XHTML validation,
# this check will at least highlight malformed HTML that might be exploited
# by a hacker.
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{CheckPurity} = 0;

