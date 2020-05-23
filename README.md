# shellup
A much more lightweight way to connect to a webshell without having to use Burp Suite.
I wrote this not out of necessity, but because I was always considering doing it one day
and given the current COVID-19 climate I finally said screw it and wrote this. In the event
that I obtain code execution on a server and am able to write a quick oneliner webshell that
looks something like this:

`<?php system($_GET['cmd']); ?>`

You can run this script and issue commands as needed. Typically all that is necessary is a
callback via a reverse shell, so this script takes care of all of the overhead necessary.

With the "shellup" function, now all you need to do is type something like:

`shellup bash`

And it will connect back to you using the /dev/tcp/ method that comes with the bash shell.
Several reverse callback methods have been preloaded into this script, but when all else fails
you can simply issue arbitrary commands via the included REPL.

Hack The Planet!