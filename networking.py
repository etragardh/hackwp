import requests, os, pickle, sys
from helpers import *
from urllib.parse import urlparse

class hwpn:
    """This is HackWP Networking class"""
    """A wrapper around python requests"""

    def __init__(self, args):
        self.args = args
        self.hwpd = get_hackwp_dir()
        self.domain = urlparse(args.target).netloc
        self.exceptions = requests.exceptions
  
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

    def get(self, url):
        if self.session_exists():
            pwarn("Attaching to session:",self.get_session_path())

        cookies = self.load_session(self.args.target) if self.session_exists() else {}
        return requests.get(url, cookies=cookies)

    def post(self, url, **args):
        if self.session_exists():
            pwarn("Attaching to session:",self.get_session_path())
        
        cookies = self.load_session(self.args.target) if self.session_exists() else {}
        json = args['json'] if 'json' in args else {}
        files = args['files'] if 'files' in args else {}
        data = args['data'] if 'data' in args else {}
        headers = args['headers'] if 'headers' in args else {}
        return requests.post(url, cookies=cookies, json=json, files=files, data=data)

    def session_extract(self):
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

