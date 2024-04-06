import requests, sys, pickle
from helpers import * 
from urllib.parse import urlparse

def session_extract(args):
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
            save_cookies(s.cookies, domain)
            psuccess("Session saved to file:")
            psuccess("~/.hackwp/"+domain+".session")

        else:
            perror("Error extracting session cookies")
            perror("Server status code:", resp.status_code)

def session_extract_help():
    return "help"
def session_auth_help():
    return "help"
