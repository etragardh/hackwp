#!/usr/bin/env python3

import argparse, os
from session import *
from helpers import * 
from scanner import * 
from importlib.machinery import SourceFileLoader

# --attack wp           --exploit installation      (unathenticated)
# --attack wp           --exploit dos               (unathenticated)
# --attack wp           --exploit login-spray       (unathenticated)
# --attack wp           --exploit user-list         (unathenticated)
#-> --attack-bricks       --attack 1.9.6-rce          (unathenticated)
# --attack-bricks       --attack 1.9.6.1-rce        (authenticated with builder edit + admin preview)
# --attack-bricks       --attack 1.9.7-rce          (authenticated with admin + builder code exec)
# --attack-breakdance   --attack 1.7.0-rce          (authenticated with builder edit)
# --attack-oxygen       --attack 4.8.1-rce          (authenticated with builder edit)
# --attack-cwicly       --attack 1.4.0.2-rce        (authenticated with contributor or above)
# --attack-wordfence    --attack 7.6.1-2fa          (unathenticated + sql read)
# --attack-layerslider  --attack 7.10.0-sqli        (unathenticated)
# --session-extract     --wp-user --wp-password     ()
#-> --session-auth                                    ()

# new syntax:
# hackwp --attack <module> --exploit <exploit> --payload <payload> --target <url> [--session-auth] [$1] [$2]
# hackwp --session-extract --wp-user <username|email> --wp-passwd <password>
# hackwp --scan --target <url>
#   scan looks for:
#   - wp users in /wp-json/wp/v2/users
#       - user names
#       - md5 hashes of emails
#       - if md5 hashes / emails are already in database
#       - if email is in have i been powned
#   - installed plugins and their versions
#   - installed themes and their versions
#   - installed version of wp core

# Parse arguments
parser = argparse.ArgumentParser(
    prog='HackWP',
    description='Utility to hack wordpress sites',
    epilog="Don't hack shit without permission! help in blueteamer discord")

parser.add_argument(
    '-y', '--version',
    action='store_true',
    help='Display version'
)
parser.add_argument(
    '-u', '--wp-user',
    help='The WP user_login or user_email'
)

parser.add_argument(
    '-p', '--wp-pass',
    help='The WP password that belongs to --wp-user'
)

parser.add_argument(
    '-s', '--session-extract',
    action='store_true',
    help=session_extract_help()
)
parser.add_argument(
    '-z', '--scan',
    action='store_true',
    help="Scan the target for vulnerabilities exploitable by HackWP"
)

parser.add_argument(
    '-v', '--verbose',
    action='store_true',
    help=session_extract_help()
)

parser.add_argument(
    '-A', '--session-auth',
    action='store_true',
    help=session_auth_help()
)

parser.add_argument(
    '-t', '--target',
    help='The target url, full url like this: https://domain.com'
)

parser.add_argument(
    '-a', '--attack',
    help='attack module'
)
parser.add_argument(
    '-e', '--exploit',
    help='exploit module'
)
parser.add_argument(
    '-x', '--payload',
    help='exploit module'
)
parser.add_argument(
    'pos', nargs='*'
)

args = parser.parse_args()
#print(args)

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
    session_extract(args)
    exit()

##
# Print version and exit
#if args.version:
#    hwp_ascii()
#    psuccess("Version:", get_version())
#    exit()

##
# Scan target and exit
if args.scan:
    scanner(args);
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
