import pickle, os, base64, re

# HackWP Version
def get_version():
    return "0.1-beta"

# HackWP directory
def get_hackwp_dir():
    return os.path.expanduser('~/.hackwp')

# Get real path to installation
def get_realpath():
    return os.path.dirname(os.path.realpath(__file__))

hackwp_dir = get_hackwp_dir() 
realpath = get_realpath() 

###
# Run ASCII art
def hwp_ascii(size='auto'):
    cols, rows = os.get_terminal_size()

    # Owl Sizes
#    if size == 'auto':
#        if cols >= 100:
#            size = 'large'
#        elif cols >= 77:
#            size = 'medium'
#        elif cols >= 75:
#            size = 'small'
#        else:
#            size = 'tiny'
    # Logo sizes
    if size == 'auto':
        if cols >= 75:
            size = 'large'
        else:
            size = 'small'

    with open(realpath + '/assets/logo.'+size+'.ascii', 'r') as f:
        print(f.read())

# Check if payload is compatible with exploit
# get_vuln is a list ['RCE', 'SQLe', 'CODEi', 'XSSs']
# get_dep is also a list ['RCE', 'SQLe', 'CODEi', 'XSSs']
# Atleast one needs to be a match
# Return the match or false
def payload_is_compatible(exploit, payload):
    e_methods = exploit.get_methods()
    p_methods = payload.get_methods()
    if not set(e_methods).isdisjoint(p_methods):
        for method in e_methods:
            if method in p_methods:
                return method 
    else:
        return False

def launch_message(exploit, payload, args):
    hwp_ascii()
    cols, rows = os.get_terminal_size()
    print("#"*(cols-1))
    print("## Attacking: " + args.target + " "*(cols-len(args.target)-17) + "##")
    print("## Surface:   " + args.attack + " "*(cols-len(args.attack)-17) + "##")
    print("## Exploit:   " + args.exploit +" by: " + exploit.get_author())
    print("## Payload:   " + args.payload +" by: " + payload.get_author())
    print("#"*(cols-1))

# Cookie helpers
#def save_cookies(requests_cookiejar, domain):
#    with open(hackwp_dir+'/'+domain+'.session', 'wb') as f:
#        pickle.dump(requests_cookiejar, f)

#def load_cookies(domain):
#    with open(hackwp_dir+'/'+domain+'.session', 'rb') as f:
#        return pickle.load(f)

## Short "unique" ID
def uid(n=8):
    b64 = base64.b64encode(os.urandom(32))[:n].decode('utf-8')
    return re.sub("(\+|\@|\\/)", 'x', b64)

####
## Print in Color

BLACK  = "\033[30m"
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
BLUE   = "\033[34m"
PURPLE = "\033[35m"
CYAN   = "\033[36m"
WHITE  = "\033[37m"
# bold
B    = "\033[1m"
BOFF = "\033[22m"

def pinfo(text, obj=""):
    print("[ ] " + text,obj)

def pwarn(text, obj=""):
    print("["+YELLOW+B+"+"+WHITE+BOFF+"] " + text,obj)

def perror(text, obj=""):
    print("["+RED+B+"-"+WHITE+BOFF+"] " + text,obj)

def psuccess(text, obj=""):
    print("["+GREEN+B+"+"+WHITE+BOFF+"] " + text,obj)
