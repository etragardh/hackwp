#!/usr/bin/env python3
from importlib.machinery import SourceFileLoader
import requests, os
from helpers import *

def scanner(args):

    vulnerabilities = [] 

    ##
    # Get taget index html
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
       
            pinfo("Scanning surface: ", surface)


            surface_scan_path = './exploits/'+surface+'/scan.py'
            surface_scan = SourceFileLoader("Scan Module",surface_scan_path).load_module()
            
            # Is this surface present?
            if not surface_scan.scan(html, args):
                pinfo(" -> Surface not present on target")
                continue
            else:
                pwarn(" -> Surface present on target")

            for exploit in os.listdir("exploits/"+surface):
                if exploit == '__pycache__' or exploit.startswith('scan.py'):
                    continue
                pinfo(" -> Scanning for exploit:", exploit)
                exploit_scan_path = './exploits/'+surface+'/'+exploit+'/scan.py'
                exploit_scan = SourceFileLoader("Scan Module",exploit_scan_path).load_module()

                if exploit_scan.scan(html, args):
                    psuccess(" - -> Target is vulnerable to:", exploit)
                    vulnerabilities.append((surface, exploit))

        #print(os.path.join(subdir, file))
        #for surface in 
        #exploit_path = './exploits/'+module+'/'+exploit+'/main.py'
        #exploit = SourceFileLoader("xploit Module",exploit_path).load_module()

    else:
        perror("Target has a server error")
        perror("",r.status_code)
    
    print(vulnerabilities)
