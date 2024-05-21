from helpers import md5sum, get_domain, get_hackwp_dir
from networking import hwpn
import os, json, re, time
from debug import hwpd


class respObj:
    def __init__(self, json_object):
        self.url            = json_object['url']
        self.status_code    = json_object['status_code']
        self.text           = json_object['text']

# Use case

# Crawl entires website
# - save results to cache for later use

# Crawl for version of wordpress (entire website, as backup)

# Fetch theme used (only startpage)

# Crawl for plugins used (entire website)

# Fetch plugins used (specific folders, save response code)
# - agressive scanning

# Crawl s


class hwpc:

    def __init__(self, args):
        self.args = args
        self.n = hwpn(args)
        self.domain = get_domain(args.target)
        self.d = hwpd(args.debug)

    # Crwal entire website, all pages
    def crawl(self, url, pattern, group=False, crawled=[], exclude=True):
        if crawled == []:
            pass
#            print("="*20)
#            print("New Crawl of:", url)
#            print("="*20)

        # Dont crawl the same url twice
        if md5sum(url) in crawled:
 #           print("exists", url, md5sum(url), crawled)
            return False

        # Regex for urls to exclude from crawling
        if exclude is True:
            # Default: dont crawl wp-json|uploads|css etc
            exclude = 'wp-json|uploads|assets|\.css|\.js|\.php|\.pdf|\.jpe?g|\.png'
        if exclude is not False and re.search(exclude, url, re.IGNORECASE):
            return False

#        print("crawling:", url)

        # Add this url to crawled
        crawled.append(md5sum(url))

        # Get data (fetch can handle cache)
        resp = self.fetch(url)

        # First find patterns
        matches = re.findall(pattern, resp.text, re.IGNORECASE)
        if group is not False:
            m1 = []
            for match in matches:
                m1.append(match[group-1])
            matches = m1
        if matches:
            self.d.msg("Crawl MATCH:", matches)

        # Find more URLs present on this page
        # Only URLs starting with target
        # Wordpress uses absolute URLs if you dont really mess it up =)
        urls = self.extract_urls(resp.text, self.domain)
        for url in urls:
            m2 = self.crawl(url[0], pattern, group, crawled)
            matches = matches + m2 if m2 else matches

        # Return unique only
        #return list(dict.fromkeys(matches))
        return matches

    # Wrapper for networking.get()
    # With cache handler
    def fetch(self, url, cache=True):

        # Build cache_path
        signature = md5sum(url)
        cache_path = get_hackwp_dir() + "/" + get_domain(self.args.target) + ".cache/" + signature

        # Check for cache
        if cache and os.path.exists(cache_path):
#            print("cache: ", url)
            self.d.msg("C:",url)
            with open(cache_path, 'r') as f:
                return respObj(json.load(f))

        else:
#            print("live: ", url)
            time.sleep(.025)
            resp = self.n.get(url)
            self.d.msg(f"L: ({resp.status_code})",url)
            if resp is False:
                return False

            # Save to cache
            data = {
                'url': url,
                'status_code': resp.status_code,
                'text': resp.text
            }
            with open(cache_path, 'w+') as f:
                json.dump(data, f)

            return resp 

    # Wrapper for fetch()
    # Handles regex grep
    def rfetch(self, url=False, pattern=False, group=False, cache=True):
        if not url or not pattern:
            perror("Missing req param in rfetch()")

        resp = self.fetch(url, cache)
        if resp is False:
            return False

        matches = re.findall(pattern, resp.text, re.IGNORECASE)
        if group is not False:
            m1 = []
            for match in matches:
                m1.append(match[group-1])
            matches = m1
    
        if matches:
            return matches
        else:
            return False

    # Extract urls
    def extract_urls(self, text, domain=False):
        if domain:
            upattern = f'(https?:\/\/{domain}\/(.*?))("|\')'
        else:
            upattern = f'(https?:\/\/(.*?))("|\')'
        return re.findall(upattern, text, re.IGNORECASE)














