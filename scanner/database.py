import os, requests
from helpers import *

def get_db_last_update():
    if os.path.exists('assets/database.json'):
        return os.path.getmtime('assets/database.json')
    else:
        # create empty file
        with open('assets/database.json', 'w') as f:
            f.write('{}')
        return 0

def do_db_update():
    # Download public wordfence database
    try:
        pinfo("Downloading vulnerability database")

        url = 'https://wordfence.com/api/intelligence/v2/vulnerabilities/scanner'
        r = requests.get(url)

        # Save to database.json
        with open('assets/database.json', 'w') as f:
            f.write(r.text)
    except:
        perror("Failed to download database")
