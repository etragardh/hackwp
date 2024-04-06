#!/usr/bin/env python3

import argparse, os
from session import *
from importlib.machinery import SourceFileLoader

print("-------------------------------------")
print("--- Attack info: --------------------")
print("- Target:   https://bd.blueteamer.io")
print("- Vector:   bricks")
print("- Exploit:  1.9.6-rce")
print("- Payload:  rshell")
print("-------------------------------------")
print("+ Taget is running bricks 1.9.4")
print("+ Taget is vulnerable")
print("+ Payload installed to /rshell.php")
print("-------------------------------------")
print("- Thanks for using hackwp")
print("- Need help, visit our discord")
print("- https://discord.gg/JN55bCvp")
exit()

# --attack wp           --exploit installation      (unathenticated)
# --attack wp           --exploit dos               (unathenticated)
# --attack wp           --exploit login-spray       (unathenticated)
# --attack wp           --exploit user-list         (unathenticated)
# --attack-bricks       --attack 1.9.6-rce          (unathenticated)
# --attack-bricks       --attack 1.9.6.1-rce        (authenticated with builder edit + admin preview)
# --attack-bricks       --attack 1.9.7-rce          (authenticated with admin + builder code exec)
# --attack-breakdance   --attack 1.7.0-rce          (authenticated with builder edit)
# --attack-oxygen       --attack 4.8.1-rce          (authenticated with builder edit)
# --attack-cwicly       --attack 1.4.0.2-rce        (authenticated with contributor or above)
# --attack-wordfence    --attack 7.6.1-2fa          (unathenticated + sql read)
# --attack-layerslider  --attack 7.10.0-sqli        (unathenticated)
# --session-extract     --wp-user --wp-password     ()
# --session-auth                                    ()

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
    epilog="Don't hack shit without permission!\r\nFurther help in blueteamer discord")

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
args = parser.parse_args()
print(args)

##
# Create ~/.hackwp directory if not exists
hackwp_dir = os.path.expanduser('~/.hackwp')
if not os.path.isdir(hackwp_dir):
    print("~/.hackwp path not found..")
    try:
        os.mkdir(hackwp_dir)
        print("~/.hackwp created")
    except OSError as error:
        print(error)

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
# Start attack mode
if args.attack:
    if not args.exploit:
        print("--exploit is required")
        exit()
    module  = args.attack
    exploit = args.exploit
    exploit_path = './modules/'+module+'/'+exploit+'/main.py'
    mod = SourceFileLoader("Attack Module",exploit_path).load_module()
    mod.attack(args)
    exit()

###
# Run ASCII art
with open('owl.ascii', 'r') as f:
    print(f.read())
