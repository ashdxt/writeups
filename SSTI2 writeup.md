This is a medium [PicoCTF challenge](https://play.picoctf.org/practice?category=1&page=1&search=SSTI2)

####  Problem Description

I made a cool website where you can announce whatever you want! I read about input sanitization, so now I remove any kind of characters that could be a problem :)I heard templating is a cool and modular way to build web apps! Check out my website.



I would recommend you read the writeup for [[SSTI1 writeup]] first
or read through my notes on [[server]]

It's pretty similar to SSTI1



we can pretty clearly see that the webpage reflects user input
![[Pasted image 20251016204435.png]]



###Detection/identification

the post request in burp suite:
![[Pasted image 20251016204631.png]]



sending this to intruder for figuring out if a SSTI vuln exists and  identifying the templating engine 
![[Pasted image 20251016204818.png]]

Burpsuite intruder loops through the list of payloads I've provided to it, sending a request with each payload, replacing  ``$test$ `` in the HTTP request below with a particular payload

 I've setup the variable content in the HTTP request as the "loop field" and for the payloads I'm using it's a combination of https://cheatsheet.hackmanit.de/template-injection-table/ and
 https://github.com/payloadbox/ssti-payloads (there are better payload lists but this does the job for a challenge like this)


![[Pasted image 20251016205150.png]]

Further note: grep etestxtract  would be really good to add for this use but I don't have burpsuite premium : ( , (it automatically extracts the text from the output webpage and displays it in the results table)


after looking through the payloads, I was able to see that the jinja2 one worked, now that we know jinja2 is the templating engine, we can try jinja2 payloads

we can see that the website really doesn't like attempts at SSTI injections: 

![[Pasted image 20251016212723.png]]


I was able to get past this by using this bypass after looking a while

I used this to find the bypass, also on payloadalthethings (https://techbrunch.github.io/patt-mkdocs/Server%20Side%20Template%20Injection/#jinja2-filter-bypass)
https://onsecurity.io/article/server-side-template-injection-with-jinja2/


```
```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```
``


resulting in the command 'id' being ran

![[Pasted image 20251016211948.png]]

from here on out you have RCE, it's trivial to get the flag by editing the commands being run to ls and then cat flag.txt

