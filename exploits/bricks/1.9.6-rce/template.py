##
# Module:       bricks
# Exploit:      1.9.6-rce
# Description:  unauthenticated RCE against bricks version up to 1.9.6

##
# Attack
# Performs the actual attack
# Requires a payload & target

def attack(args):
    print("attacking from bricks rce exploit")

##
# Test
# Perform tests against target to determine if vulnerable
# This is very similar to attack() however the payload should
# be self descruct/non persistant and return true/false
# No false positives are accepted here

def test(args):
    print("Performing tests")


##
# Scan
# Perform a scan against the target to determine if it
# _might_ be vulnerable. ie checking versions.
# No actual exploit is done during scan
# False positives are accepted.

def scan(args):
    print("Performing scan")


##
# Help
# Display help text

def help():
    print("This is the help")
