#!/usr/bin/env python3
from importlib.machinery import SourceFileLoader
import time
import requests, os
from helpers import *
from scanner.database import *
from networking import hwpn
from scanner.core import hwpsc
from scanner.theme import hwpst
from scanner.plugins import hwpsp

class hwps:

    def __init__(self, args):
        self.args = args
        self.html = ''
        self.core = {
            'version': ''
        }
        self.theme = {
            'slug': '',
            'version': ''
        }
        self.users = []
        self.plugins = []
        self.vulnerabilities = []

    def scan(self):
        # Scanner

        # Check: Database
        # - last update of wordfence?
        # - last update of patchstack? (live?)

        last_db_update = get_db_last_update()
        accepted_last_update = time.time() - 60*60*24*7 # 7 days

        if last_db_update <= accepted_last_update:
            # Do update
            pwarn("Your database is old, we update it for you now..")
            do_db_update(self.args)
        elif self.args.verbose:
            pwarn("Your database was updated recently..")

        # Get index html
#        req = hwpn(self.args)
#        resp = req.get(self.args.target)
#        if resp and resp.status_code != 200:
#            perror("Could not connect to host")
#            perror("Status: ",resp.status_code)
#            exit()
#        html = resp.text
#        self.html = html

        # Scan: WP Core
        # - Version
        core = hwpsc(self.args)
        self.core['version'] = core.get_version()

        msg = self.core['version'] if self.core['version'] else 'unknown'
        pinfo("WP Core version:", msg) 

        # Scan: Theme
        # - slug
        # - version
        theme = hwpst(self.args)
        self.theme['version'] = theme.get_version()
        self.theme['slug'] = theme.get_slug()

        msg = self.theme['slug'] if self.theme['slug'] else 'unknown'
        pinfo("WP Theme:", msg) 

        msg = self.theme['version'] if self.theme['version'] else 'unknown'
        pinfo("WP Theme Ver:", msg) 
        
        # Scan: Plugins
        # - plugins installed or present
        # - versions (scan for readme.txt, this file is required for plugins in the public wp repo)
        # - wp is also recommending to move changelog to changelog.txt (but keep one most recent in readme.txt)

        plugins = hwpsp(self.args, self.core['version'])
        self.plugins = plugins.get_plugins()


        for slug in self.plugins:
            version = self.plugins[slug] if self.plugins[slug] is not False else "Unknown"
            pwarn(f"Found plugin: {slug} (v: {version})")

        exit()
        # Scan: Users
        # - usernames
        # - ID

        # Scan: vulnerabilities
        # - vulnerable according to wordfence
        # - vulnerable according to patchstack
        # - vulnerable according to exploits

    ## Old "scan()"
    def scan_plugins_old(self):
        args = self.args

        ##
        # Get target index html
        try:
            r = requests.get(args.target)
        except(requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            perror("Host seems to be offline")
            exit()

        if r.status_code == 200:
            html = r.text

            for surface in os.listdir("exploits/"):
                if surface == '__pycache__':
                    continue
           
                #pinfo("Scanning surface: ", surface)


                surface_scan_path = './exploits/'+surface+'/scan.py'
                surface_scan = SourceFileLoader("Scan Module",surface_scan_path).load_module()
                
                # Is this surface present?
                if not surface_scan.scan(html, args):
                    #pinfo(" -> Surface not present on target")
                    continue
                else:
                    pwarn("Surface ("+surface+") present on target")

                for exploit in os.listdir("exploits/"+surface):
                    if exploit == '__pycache__' or exploit.startswith('scan.py'):
                        continue
                    pinfo(" -> Scanning for exploit:", exploit)
                    exploit_scan_path = './exploits/'+surface+'/'+exploit+'/scan.py'
                    exploit_scan = SourceFileLoader("Scan Module",exploit_scan_path).load_module()

                    if exploit_scan.scan(html, args):
                        psuccess(" - -> Target is vulnerable to:", exploit)
                        self.vulnerabilities.append((surface, exploit))

            #print(os.path.join(subdir, file))
            #for surface in 
            #exploit_path = './exploits/'+module+'/'+exploit+'/main.py'
            #exploit = SourceFileLoader("xploit Module",exploit_path).load_module()

        else:
            perror("Target has a server error")
            perror("",r.status_code)
        
        if len(self.vulnerabilities) >= 1:
            psuccess("=======================================")
            psuccess("Your target is vulnerable")
            for surface, exploit in self.vulnerabilities:
                psuccess("try: hackwp --target " + args.target + " --attack " +surface+" --exploit " +exploit+ " --payload rce-test")

        else:
            perror("=======================================")
            perror("Your target is _not_ vulnerable")
