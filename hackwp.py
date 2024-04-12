#!/usr/bin/env python3

import os
#from session import *
from helpers import * 
from scanner import hwps 
from importlib.machinery import SourceFileLoader

from networking import hwpn
from parser import hwp_parser as hwpp

# Parse arguments
parser = hwpp.create()
args = parser.parse_args()

##
# Create ~/.hackwp directory if not exists
hackwp_dir = get_hackwp_dir() 
if not os.path.isdir(hackwp_dir):
    perror("~/.hackwp path not found..")
    try:
        os.mkdir(hackwp_dir)
        pinfo("~/.hackwp created")
    except OSError as error:
        perror(error)

##
# Normalize --target
if args.target:
    args.target = args.target.strip("/")

##
# Extract sessions and exit
if args.session_extract:
    n = hwpn(args)
    n.session_extract()
    exit()

##
# Scan target and exit
if args.scan:
    s = hwps(args)
    s.scan();
    exit()

##
# Start attack mode
if args.attack:
    if not args.exploit or not args.target or not args.payload:
        perror("--exploit is required")
        perror("--target is required")
        perror("--payload is required") # smitka-browser
        exit()
    module  = args.attack
    exploit = args.exploit
    exploit_path = './exploits/'+module+'/'+exploit+'/main.py'
    payload_path = './payloads/'+args.payload+'/main.py'
    exploit = SourceFileLoader("Exploit Module",exploit_path).load_module()
    payload = SourceFileLoader("Payload Module",payload_path).load_module()

    if not payload_is_compatible(exploit, payload): 
        perror("This payload is not available for this exploit")
        pwarn("Exploit can handle:", exploit.get_vuln())
        pwarn("The payload needs", payload.get_dep())
        exit()

    # Go
    pinfo("===================================================")
    pinfo("== HackWP") 
    pinfo("== by @etragardh") 
    pinfo("===================================================")
    pinfo("== Attacking: "+args.target) 
    pinfo("== Surface: "+args.attack)
    pinfo("== Exploit: "+args.exploit) 
    pinfo("== Payload: "+args.payload)
    pinfo("===================================================")
    exploit.attack(args, payload)
    exit()

hwp_ascii()
psuccess("Version:", get_version())

r = hwpn(args)
res = r.post(args.target, json={'testing':'test'})
print(res.text)
