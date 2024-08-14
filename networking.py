import requests, os, pickle, sys, random
from helpers import *
from urllib.parse import urlparse
from debug import hwpd

class hwpn:
    """This is HackWP Networking class"""
    """A wrapper around python requests"""

    def __init__(self, args):
        self.args = args
        self.hwpd = get_hackwp_dir()
        self.domain = urlparse(args.target).netloc
        self.exceptions = requests.exceptions
        self.d = hwpd(args.debug)

    def get_session_path(self):
        return self.hwpd+'/'+self.domain+'.session'

    def save_session(self, requests_cookiejar, domain):
        with open(self.get_session_path(), 'wb') as f:
            pickle.dump(requests_cookiejar, f)

    def load_session(self, domain):
        with open(self.get_session_path(), 'rb') as f:
            return pickle.load(f)

    def session_exists(self):
        return os.path.exists(self.get_session_path())

    def get_spoofed_header(self, headers, ip=True, ua=True):
        if ip is True:
            a = random.randint(1,254)
            b = random.randint(1,254)
            c = random.randint(1,254)
            d = random.randint(1,254)
            spoofed_ip = f'{a}.{b}.{c}.{d}'
            headers = {
                **headers,
                'HTTP_CF_CONNECTING_IP': spoofed_ip,
                'HTTP_CLIENT_IP': spoofed_ip,
                'HTTP_X_FORWARDED_FOR': spoofed_ip,
                'HTTP_X_FORWARDED': spoofed_ip,
                'HTTP_X_REAL_IP': spoofed_ip
            }
        if ua is True:
            with open(get_realpath() + '/user-agents.txt', 'r') as f:
                user_agents = f.readlines()

            rnd = random.randint(0, len(user_agents)-1)
            spoofed_ua = user_agents[rnd].strip()

            headers = {
                **headers,
                'User-Agent': spoofed_ua
            }
        else:
            headers = {
                **headers,
                'User-Agent': 'HackWP/' + get_version()
            }
        return headers


    def get(self, url, **args):

        ##
        # Attach to session if possible
        if self.args.auth and self.session_exists() and self.args.verbose:
            pwarn("Attaching to session:",self.get_session_path())

            cookies = self.load_session(self.args.target) \
                if self.session_exists() else {}

        else: 
            cookies = args['cookies'] if 'cookies' in args else {}

        ##
        # Spoof IP
        headers = args['headers'] if 'headers' in args else {}
        headers = self.get_spoofed_header(headers, not self.args.no_spoof_ip,not self.args.no_spoof_ua)

        #headers = {**headers, 'User-Agent':'HackWP/'+get_version()}

        ##
        # Connect
        try:
            resp = requests.get(url, cookies=cookies, headers=headers)
            #resp = requests.get(url) 
        except requests.exceptions.Timeout as e:
            # Maybe set up for a retry, or continue in a retry loop
            raise SystemExit(e)
            resp = False
        except requests.exceptions.TooManyRedirects as e:
            # Tell the user their URL was bad and try a different one
            raise SystemExit(e)
            resp = False
        except requests.exceptions.RequestException as e:
            # catastrophic error. bail.
            raise SystemExit(e)
            resp = False

        return resp

    def post(self, url, **args):
        if self.args.auth and self.session_exists() and self.args.verbose:
            pwarn("Attaching to session:",self.get_session_path())
        
            cookies = self.load_session(self.args.target) \
                if self.session_exists() else {}

        else:
            cookies = args['cookies'] if 'cookies' in args else {}

        ##
        # Prepare data
        json = args['json'] if 'json' in args else {}
        files = args['files'] if 'files' in args else {}
        data = args['data'] if 'data' in args else {}
        headers = args['headers'] if 'headers' in args else {}

        ##
        # Spoof IP
        headers = self.get_spoofed_header(headers, not self.args.no_spoof_ip, not self.args.no_spoof_ua)
        #headers = {**headers, 'User-Agent':'HackWP/'+get_version()}

        ##
        # Connect
        try:
            resp = requests.post( \
                    url, cookies=cookies, json=json, \
                    files=files, data=data, headers=headers \
            )
        except requests.exceptions.Timeout as e:
            # Maybe set up for a retry, or continue in a retry loop
            raise SystemExit(e)
            resp = False
        except requests.exceptions.TooManyRedirects as e:
            # Tell the user their URL was bad and try a different one
            raise SystemExit(e)
            resp = False
        except requests.exceptions.RequestException as e:
            # catastrophic error. bail.
            raise SystemExit(e)
            resp = False

        return resp

    def extract_auth(self):
        args = self.args
        ## Argument check
        if not args.target or not args.wp_user or not args.wp_pass:
            perror("Missing required argument")
            pwarn("Required arguments when extracting a session:")
            pwarn("--wp-user")
            pwarn("--wp-pass")
            pwarn("--target")
            exit()

        ## Get domain from URL
        domain = urlparse(args.target).netloc

        # Contacts
        wp_login = args.target+'/wp-login.php'
        wp_admin = args.target+'/wp-admin/'

        # Attack
        with requests.Session() as s:
            headers1 = { 'Cookie':'wordpress_test_cookie=WP Cookie check' }
            datas={
                'log':args.wp_user, 'pwd':args.wp_pass, 'wp-submit':'Log In',
                'redirect_to':wp_admin, 'testcookie':'1'
            }
            s.post(wp_login, headers=headers1, data=datas)
            resp = s.get(wp_admin)
            if resp.status_code == 200:
                psuccess("Status:",resp.status_code)

                # Save session to file
                self.save_session(s.cookies, domain)
                psuccess("Session saved to file:")
                psuccess("~/.hackwp/"+domain+".session")

            else:
                perror("Error extracting session cookies")
                perror("Server status code:", resp.status_code)

