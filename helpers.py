import pickle, os

# HackWP directory
def get_hackwp_dir():
    return os.path.expanduser('~/.hackwp')

hackwp_dir = get_hackwp_dir() 

# Check if payload is compatible with exploit
# get_vuln is a list ['RCE', 'SQLi', 'CODEi', 'XSSs']
# get_dep is also a list ['RCE', 'SQLi', 'CODEi', 'XSSs']
# Atleast one needs to be a match
def payload_is_compatible(exploit, payload):
    return not set(exploit.get_vuln()).isdisjoint(payload.get_dep())


# Cookie helpers
def save_cookies(requests_cookiejar, domain):
    with open(hackwp_dir+'/'+domain+'.session', 'wb') as f:
        pickle.dump(requests_cookiejar, f)

def load_cookies(domain):
    with open(hackwp_dir+'/'+domain+'.session', 'rb') as f:
        return pickle.load(f)


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
