import os, requests
from helpers import *
from networking import hwpn

def get_db_last_update():
    ## Just checking one file is enough.
    ## We update all at once
    
    realpath = get_realpath()
    vuln_path = realpath + '/assets/scanner/vulnerabilities.json'

    if os.path.exists(vuln_path):
        return os.path.getmtime(vuln_path)
    else:
        # create empty file
#        with open(vuln_path, 'w') as f:
#            f.write('{}')
        return 0

def do_db_update(args):
    n = hwpn(args)
    realpath = get_realpath()
    vuln_path = realpath + '/assets/scanner/vulnerabilities.json'
    wp_path = realpath + '/assets/scanner/wp.json'

    # Download public wordfence database
    try:
        if args.verbose: pinfo("Downloading vulnerability database")

        url = 'https://wordfence.com/api/intelligence/v2/vulnerabilities/scanner'
        r = n.get(url)

        # Save to database.json
        with open(vuln_path, 'w+') as f:
            f.write(r.text)
    except:
        perror("Failed to download database")

    # Download WP Core Database
    try:
        if args.verbose: pinfo("Downloading WP Core versions database")
        r = requests.get('https://api.wordpress.org/core/stable-check/1.0/')
        with open(wp_path, 'w+') as f:
            f.write(r.text)
    except:
        perror("Fail to download wp core database")

#def download_wp_core_checksums(version):
#    realpath = get_realpath()
#    base_path = realpath + '/assets/scanner/'
#    if not os.path.exists(base_path + f'wp_{version}.json'):
#        with requests.get(f'https://api.wordpress.org/core/checksums/1.0/?version={version}&locale=en_US') as r:
#            with open(base_path + f'wp_{version}.json', 'w') as f:
#                f.write(r.text)

#def get_wp_core_checksum():
#    pass
