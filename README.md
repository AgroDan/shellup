# shellup
A much more lightweight way to connect to a webshell without having to use Burp Suite.
I wrote this not out of necessity, but because I was always considering doing it one day
and given the current COVID-19 climate I finally said screw it and wrote this. In the event
that I obtain code execution on a server and am able to write a quick oneliner webshell that
looks something like this:

`<?php system($_GET['cmd']); ?>`

I can simply run this script and issue my commands. Typically all I want to do is run a reverse
shell, so this script takes care of the URL Encoding for you.
