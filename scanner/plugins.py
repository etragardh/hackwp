from networking import hwpn
from helpers import pinfo, pwarn, get_domain, get_hackwp_dir, get_realpath, file_get_json, is_valid_version
import re, json, os#, requests, hashlib
#from urllib.parse import urlparse
#from packaging.version import Version
from scanner.crawler import hwpc
class hwpsp:

    def __init__(self, args, core_version = False):
        self.args = args
        self.crawler = hwpc(args)
        self.core_version = core_version

    # Return:
    # {
    #   'woocommerce': '1.2.3',
    #   'breakdance': '1.7.0'
    # }
    def get_plugins(self):

        # Step 1 - Crawl 
        plugins = self.get_crawled_plugins()
#        print("crawled:", crawled_plugins)

        # Step 2 - Agressive scanning
        if self.args.agressive:
            pwarn("Starting agressiv scan of plugins")
            pwarn(" - > This might take a while")
            other_plugins = self.get_other_plugins(plugins)
    
            # Merge
            plugins = {**plugins, **other_plugins} 

        return plugins

    def get_crawled_plugins(self):
        pattern = 'wp-content\/plugins\/(.*?)\/'
        slugs = self.crawler.crawl(self.args.target, pattern)
#        print(slugs)

        plugins = {}
        for slug in slugs:
            version = self.get_version(slug)
            plugins[slug] = version

        return plugins

    def get_other_plugins(self, verified_plugins = False):

        accepted_status_codes = [200, 400, 401, 403, 500]

        vulnerable_plugins = self.get_vulnerable_plugins()

        other_plugins = {}
        for slug in vulnerable_plugins:
            if slug not in verified_plugins:
                uri = f'/wp-content/plugins/{slug}/'
                url = self.args.target + uri
                resp = self.crawler.fetch(url)
                
                if resp is False:
                    continue

                status = resp.status_code

                if status in accepted_status_codes:
                    other_plugins[slug] = self.get_version(slug)

        return other_plugins

    def get_vulnerable_plugins(self):
#        return ['test1', 'test2', 'test3', 'contact-plugin', 'akismet', 'finns-inte', 'hello-dolly', 'blocks']
        vulnerable_plugins = []
        path = get_realpath() + '/assets/scanner/vulnerabilities.json'
        with open(path) as db:
            entries = json.load(db)
            for entry in entries:
                if entries[entry]['software'][0]['type'] == 'plugin':
                    vulnerable_plugins.append(entries[entry]['software'][0]['slug'])

        return vulnerable_plugins

    ##
    # HackWP needs to know what version of This plugin 
    # the target site is running
    def get_version(self, slug):

        # Method 1 - inspect readme.txt
        #
        uri = f'/wp-content/plugins/{slug}/readme.txt'
        url = self.args.target + uri
        pattern = '= (([0-9]{1,3})(\.[0-9]{1,3})(\.[0-9]{1,3})?(\.[0-9]{1,3})?)(.*?)='
        version = self.crawler.rfetch(url, pattern)
        if is_valid_version(version):
            return version

        # Method 2 - inspect changelog.txt
        #
        uri = f'/wp-content/plugins/{slug}/changelog.txt'
        url = self.args.target + uri
        # Re use pattern from above
        version = self.crawler.rfetch(url, pattern)
        if is_valid_version(version):
            return version


        #
        # Method 3 - crawl entire website
        # Bug in Python??
        # Why does python remember 'crawled' variable from last crawl?
        # I need to set it to empty array to start new craw =)
        pattern = f'wp-content\/plugins\/{slug}\/(.*?)ver=(.*?)("|\')'
        versions = self.crawler.crawl(self.args.target, pattern, 2, []) 
#        print("v:", versions)

        valid_versions = []
        for version in versions:
            if not is_valid_version(version):
                continue

            if self.core_version and version == self.core_version:
                continue
                    
            valid_versions.append(version)

        if valid_versions:
            # Return the most frequent
            return max(set(valid_versions), key = valid_versions.count)

        #
        # Method 4 - cryptografic checksums
        #            we can get checksums for a specific version of a plugin
        #            from wordpress.org

        # We dont know
        return False
