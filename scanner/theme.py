from networking import hwpn
#from helpers import pinfo, pwarn, get_hackwp_dir, get_realpath, file_get_json
import re# os, requests, hashlib
#from urllib.parse import urlparse
from packaging.version import Version
from scanner.crawler import hwpc
class hwpst:

    def __init__(self,args):
        self.args = args
        self.crawler = hwpc(args)

    def get_slug(self):
        # Method 1 - regex on index
        resp = self.crawler.fetch(self.args.target)
        slug = self.get_slug_regex_on_index(resp.text)

        if slug:
            return slug

        # Method 2 - 

        return False

    def get_slug_regex_on_index(self, html):
        match = re.search('wp-content\/themes\/(.*?)\/', html)
        if match:
            return match.group(1)

        return False

    ##
    # HackWP needs to know what version of WP Core
    # the target site is running
    # get all checksums for latest
    # get all checksums for 2nd to latest
    # get all checksums in latest, that are different
    # if there is just one single match, we know it is a HIT
    def get_version(self):
        # Method 1 - inspect style.css

        version = self.get_version_from_style_css()
        if version:
            return version

        return False

    def get_version_from_style_css(self):
        slug = self.get_slug()
        if not slug:
            return False

        url = self.args.target + "/wp-content/themes/" + self.get_slug() + "/style.css"
        n = hwpn(self.args)
        resp = n.get(url)

        match = re.search('Version: (.*?)([\r\n]|\r\n)', resp.text, re.IGNORECASE)
        try:
            if match and match.group(1):
                if Version(match.group(1)) >= Version("1"):
                    return match.group(1)
        except:
            if isinstance(match.group(1), str):
                return match.group(1)

        return False
