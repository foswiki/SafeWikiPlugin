#---+ Extensions
#---++ SafeWikiPlugin
# **SELECT FAIL,ASSERT,WARN**
# If set to FAIL, then threats will be defused. If set to WARN, then Foswiki
# will continue to operate normally and any threats are logged to the error
# log without being disarmed (this is useful when tuning the filters for
# a specific site). ASSERT is like FAIL except that if FOSWIKI_ASSERTS are
# enabled, it will fail with an ASSERT on the first filter action.
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{Action} = 'FAIL';

# **BOOLEAN**
# If this option is enabled, then the plugin will check HTML for
# correctness. While nowhere near as rigorous as a full XHTML validation,
# this check will at least highlight malformed HTML that might be exploited
# by a hacker.
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{CheckPurity} = 0;

# **STRING**
# Choose a secret(!) key to be used for signing/verifying code snippets.
# If anyone can guess or bruteforce it, it'll make this plugin completely
# useless.
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{SecretKey} = 'this is a bad key';

# **PERL**
# A perl list consisting of SHA-256 based signatures of inline script code that
# may appear anywhere in a topic, including as event handlers, script tags, or
# added with the %ADDTO macros.
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{SignaturesList} = [];

# **STRING 60**
# Optional topic containing a list of signatures merged with the above list.
# The plugin only uses the first column of the table found in this topic.  See
# System.SafeWikiSignatures for an example.  <b>If topic based signatures are
# used it is critical that this topic cannot be modified by unauthorized
# users.</b>
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{SignaturesTopic} = '';

#---+++ Event Handlers
# **PERL**
# Array of perl regular expressions, one of which must match the value
# of an on* handler, or it will be filtered. Here's an expression you can add
# to permit a simple function call:
# <tt>'^(\\s*javascript:)?(\\s*return)?\\s*\\w+\\s*\\(((\\w+|"[^"\\\\]*"|\'[^\'\\\\]\')(\\s*,\\s*(\\w+|"[^"\\\\]*"|\'[^\'\\\\]\'))*|\\s*)?\\)[\\s;]*(return\\s+(\\w+|"[^"\\\\]*"|\'[^\'\\\\]*\')[\\s;]*)?$'</tt>
# An example of a code snippet that would be accepted:
# <tt>javascript: fn(param1, param2)</tt>
# Arbitrary string constants and complex data structures cannot be parsed with
# regular expressions and hence are not let through. For practicality, a
# restricted class of string constants that don't contain escaped characters is
# accepted.
# Note that accepting function calls like that might compromise the security
# of SafeWikiPlugin in some cases.
# You can use other Foswiki::cfg variables in the the strings here.
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{SafeHandler} = [
          '^StrikeOne\.submit\(this\);?(document\.loginform\.foswiki_origin\.value\+=window\.location\.hash)?$',
        ];

# **STRING 30**
# String used to replace dodgy handlers.
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{DisarmHandler} = '/* Handler filtered by SafeWikiPlugin */';
# **BOOLEAN**
# By default, inline script blocks are replaced with a generic comment. If you
# want to see what got filtered, enable this to get a comment containing an
# escaped version of the original code.
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{ShowFilteredCode} = 0;

#---+++ URIs
# **PERL**
# HTML tags and attributes that will be URI-filtered by the SafeWikiPlugin.
# These tag/attribute combinations are filtered if the attribute's value
# matches any expression in {Plugins}{SafeWikiPlugin}{UnsafeURI} or fails to
# match at least one expression in {Plugins}{SafeWikiPlugin}{SafeURI} (if any
# are defined). The following quick reference lists all the URI attributes on
# all HTML4 & HTML5 tags, should you want to include any of them.
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
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{URIAttributes} = {
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

# **STRING 30**
# String used to replace dodgy URIs. Can be a URI if you want.
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{DisarmURI} = 'URI filtered by SafeWikiPlugin';

#---+++ SCRIPT tags
# **PERL**
# Array of perl regular expressions, one of which must match the contents
# of an inline script tag or it will be filtered. The default permits a simple
# Allows the TinyMCEPlugin to provide its inline init code.
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{SafeInline} = [];

#---+++ Other tags
# **STRING**
# Comma-separated list of tags to completely remove from the output.
$Foswiki::cfg{Plugins}{SafeWikiPlugin}{StripTags} = "FRAME,IFRAME";

