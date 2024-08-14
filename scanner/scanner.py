from importlib.machinery import SourceFileLoader
import time
import requests, os
from helpers import *
from scanner.database import *
from networking import hwpn
from scanner.core import hwpsc
from scanner.theme import hwpst
from scanner.plugins import hwpsp
from scanner.users import hwpsu
from scanner.vuln import hwpv
from scanner.exploits import hwpe
from debug import hwpd

class hwps:

    def __init__(self, args):
        self.args = args
        self.d = hwpd(args.debug)
        self.core = {
            'version': ''
        }
        self.theme = {
            'slug': '',
            'version': ''
        }
        self.plugins = {} 
        self.users = []
        self.vulnerabilities = []

    def scan(self):
        # Scanner

        # Check: Database
        # - last update of wordfence?
        # - last update of patchstack? (live?)

        last_db_update = get_db_last_update()
        accepted_last_update = time.time() - 60*60*24*7 # 7 days

        if  last_db_update <= accepted_last_update:
            # Do update
            pwarn("Your database is old, we update it for you now..")
            do_db_update(self.args)
        elif self.args.verbose:
            pinfo("Your database was updated recently..")

        # Vulnerability handler
        vuln = hwpv(self.args)

        # Scan: WP Core
        # - Version
        self.d.msg("Start scan of core")
        core = hwpsc(self.args)
        self.core['version'] = core.get_version()

        msg = self.core['version'] if self.core['version'] else 'unknown'
        pinfo("WP Core version:", msg)

        # Output if it is vulnerable
        vuln.core(self.core['version'])

        pinfo("")

        # Scan: Theme
        # - slug
        # - version
        self.d.msg("Start scan of theme")
        theme = hwpst(self.args)
        self.theme['version'] = theme.get_version()
        self.theme['slug'] = theme.get_slug()

        msg = self.theme['slug'] if self.theme['slug'] else 'unknown'
        pinfo("WP Theme:", msg) 

        msg = self.theme['version'] if self.theme['version'] else 'unknown'
        pinfo("WP Theme Ver:", msg) 
        
        # Output if it is vulnerable
        vuln.theme(self.theme['slug'], self.theme['version'])
        
        pinfo("")
        # Scan: Plugins
        # - plugins installed or present

        pinfo("Enumarate plugins")
        pinfo(" -> This might take a while")
        plugins = hwpsp(self.args, self.core['version'])
        self.plugins = plugins.get_plugins()
        pinfo("")
        for slug in self.plugins:
            version = self.plugins[slug] if self.plugins[slug] is not False else "Unknown"
            pinfo(f"Found plugin: {slug} (v: {version})")

            # Output if it is vulnerable
            vuln.plugin(slug, self.plugins[slug])
        pinfo("")

        # Scan: Users
        # - usernames
        # - ID

        pinfo("Enumerate users")
        pinfo(" -> This might take a while")
        users = hwpsu(self.args)
        self.users = users.get_users()

        for user in self.users:
            pwarn("Found user:", user)
        
        #TODO: scan for emails


        # What exploits do we have on FS that is a match?
        exploits = hwpe(self.args, self.core, self.theme, self.plugins)
        exps = exploits.scan()

        pinfo("")
        if len(exps) >= 1:
            perror("Website is vulnerable to the following HackWP exploits")
            for exp in exps:
                perror(f"-> {exp['surface']}/{exp['exploit']} (by {exp['author']})")
                pwarn(f" - methods: {exp['methods']}")
                pwarn(f" - auth: {exp['auth']}")
                exploits.next_move(exp['surface'], exp['exploit'], exp['methods'], exp['auth'])
                pinfo("")

        else:
            pinfo("HackWP has no exploits working for this website")
            pinfo("You can create one and send a pull request to git")

        exit()
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
