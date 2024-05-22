import pickle, os, base64, re, json, hashlib
from urllib.parse import urlparse
from packaging.version import Version

# HackWP Version
def get_version():
    return "0.1-alpha"

# HackWP directory
def get_hackwp_dir():
    return os.path.expanduser('~/.hackwp')

# print progress bar
def print_progress(progress):
    if progress >= 2:
        print('\033[F')
        print('\033[F' + WHITE+"[-] " + str(progress) + ' %')
    else:
        print(WHITE+"[-] " + str(progress) + ' %')

    if progress >= 90:
        print('\033[F')
        print('\033[F' + WHITE+"[-] " + '100' + ' %')

# Get real path to installation
def get_realpath():
    return os.path.dirname(os.path.realpath(__file__))

hackwp_dir = get_hackwp_dir() 
realpath = get_realpath() 

def get_domain(url):
    return urlparse(url).netloc

def md5sum(string):
    return hashlib.md5(string.encode("utf-8")).hexdigest()

def most_frequent(arr):
    return max(set(arr), key = arr.count)

def is_valid_version(version):
    if type(version) != str:
        return False

    # Dont accept string without .
    if "." not in version:
        return False

    # Dont accept pure timestamps
    if re.match('[0-9]{10}', version):
        return False

    # Check if version is valid and above or equal to 1.0
    try:
        return Version(version) >= Version("1")
    except:
        return False

def get_unique(obj):
    # Unique only
    if type(obj) == list:
        return list(dict.fromkeys(obj))
    else:
        return False

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

def scan_message(args):
    hwp_ascii()
    cols, rows = os.get_terminal_size()
    print("#"*(cols-1))
    print("## Scanning: " + args.target + " "*(cols-len(args.target)-17) + "##")
    print("#"*(cols-1))

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

END = "\033[0m"

def pinfo(text, obj=""):
    print(WHITE+"[-] " + text,obj)

def pbinfo(text, obj=""):
    print(END+"[-] " + text,obj)

def pwarn(text, obj=""):
    print(WHITE+"["+YELLOW+B+"+"+WHITE+BOFF+"] " + text,obj)

def perror(text, obj=""):
    print(WHITE+"["+RED+B+"x"+WHITE+BOFF+"] " + text,obj)

def pdebug(text, obj='', obj2=''):
    print(WHITE+"["+CYAN+B+"D"+WHITE+BOFF+"] " + text, obj, obj2)

def psuccess(text, obj=""):
    print(WHITE+"["+GREEN+B+"+"+WHITE+BOFF+"] " + text,obj)

##
# Get file from local file system
# Return json
def file_get_json(filepath):
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except: 
        perror("Could not open file and load as json: ",filepath)

##
# Get file from local file system
# Return string
def get_file_contents(filepath):
    try:
        with open(filepath, 'r') as f:
            return f.read()
    except:
        perror("Could not open file: ",filepath)
