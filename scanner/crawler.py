from helpers import print_progress, md5sum, get_domain, get_hackwp_dir
from networking import hwpn
import os, json, re, time
from debug import hwpd

class historyObj:
    def __init__(self, history):
        self.status_code = history['status_code']
        self.url = history['url']

class respObj:
    def __init__(self, json_object):
        self.url            = json_object['url']
        self.status_code    = json_object['status_code']
        self.text           = json_object['text']
        self.history        = []
        if len(json_object['history']) >= 1:
            self.history.append(historyObj(json_object['history'][0]))

# Use case

# Crawl entires website
# - save results to cache for later use
# Crawl for version of wordpress (entire website, as backup)
# Fetch theme used (only startpage)
# Crawl for plugins used (entire website)
# Fetch plugins used (specific folders, save response code)
# - agressive scanning


class hwpc:

    def __init__(self, args):
        self.args = args
        self.n = hwpn(args)
        self.domain = get_domain(args.target)
        self.d = hwpd(args.debug)

    def crawl(self, url, pattern, group=False, crawled=[], exclude=True,lvl=0):

        # How many pages have we crawled
        n = len(crawled)
        if n == 0:
            pass
        #print("n:",n)
        nmax = 100

        # Padding for debug
        p = "_"*lvl

        # If it is too many
        if n >= nmax:
            self.d.msg(f"{p}Too many crawls..")
            return [[], crawled, False]

        # This is the first one
        if crawled == []:
            self.d.msg(f"{p}New Crawl:", url)

        # Dont crawl the same url twice
        if md5sum(url) in crawled:
            self.d.msg(f"{p}Exists:", url)
            return [[], crawled, True]
        
        # Dont crawl this url bcz
        # Regex for urls to exclude from crawling
        if exclude is True:
            # Default: dont crawl wp-json|uploads|css etc
            exclude = 'wp-json|uploads|assets|\.css|\.js|\.php|\.pdf|\.jpe?g|\.png|\.woff2|\.ttf'
        if exclude is not False and re.search(exclude, url, re.IGNORECASE):
            self.d.msg(f"{p}Exluded:", url)
            return [[], crawled, True]

        #
        # OK, so we are crawling this URL
        #

        self.d.msg(f"{p}Crawl ({len(crawled)}):", url)

        progress = int(int(n)/int(nmax)*100)
        self.d.msg("progress", int(progress))
        #print("progress:", progress)

        # Add this url to crawled
        crawled.append(md5sum(url))
        n+=1

        # Get data (fetch can handle cache)
        # Get matches
        matches = self.rfetch(url, pattern, group)
        matches = matches if matches is not False else []
        self.d.msg(f"{p}Found:",matches)

        # Get URLs from this page
        #urls = self.extract_urls(resp.text, self.domain)
        upattern = f'(https?:\/\/{self.domain}\/(.*?))("|\')'
        urls = self.rfetch(url, upattern, 1)

        if urls is False:
            self.d.msg(f"{p}Zero URLs")
            return [matches, crawled, True]

        #self.d.msg(f"{p}Found URLs:",urls)
        self.d.msg(f"{p}Found {len(urls)} URLs")
        for url in urls:
            # Crawl 1 level deeper
            m = self.crawl(url, pattern, group, crawled, exclude, lvl+1)

            # Add matches from deep crawl
            matches += m[0]

            # Add crawled pages
            # All pages in crawled are also in m[1]
            crawled = m[1]
            n = len(crawled)

            # GO is false, stop Crawling
            if m[2] is False:
                self.d.msg(f"{p}Stopping ({len(crawled)})")
                return [matches, crawled, False]


        self.d.msg(f"{p}Continuing ({len(crawled)})")
        return [matches, crawled, True]
    
    # Crwal entire website, all pages
    def crawl_old(self, url, pattern, group=False, crawled=[], exclude=True, n = 0):
        # FIXME: fix this shit =)

        matches = []

        # Dont crawl thousands and thousands of pages
        nmax = 3 
        if n >= nmax:
            self.d.msg('n >= ',nmax)
            return [matches, True]

        if crawled == []:
            self.d.msg("New Crawl:", url)
#            print("="*20)
#            print("New Crawl of:", url)
#            print("="*20)

        # Dont crawl the same url twice
        if md5sum(url) in crawled:
            self.d.msg("Exists:", url)
 #           print("exists", url, md5sum(url), crawled)
            return [matches, False]

        # Regex for urls to exclude from crawling
        if exclude is True:
            # Default: dont crawl wp-json|uploads|css etc
            exclude = 'wp-json|uploads|assets|\.css|\.js|\.php|\.pdf|\.jpe?g|\.png'
        if exclude is not False and re.search(exclude, url, re.IGNORECASE):
            self.d.msg("Exluded:", url)
            return [matches, False]

#        print("crawling:", url)

        # Add this url to crawled
        crawled.append(md5sum(url))

        # Get data (fetch can handle cache)
        resp = self.fetch(url)
        n += 1

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
            n += 1
            if n >= nmax:
                return [matches, True]
            m2 = self.crawl(url[0], pattern, group, crawled, True, n)
            self.d.msg("Found deep: ", m2)
            matches = matches + m2 if m2[0] else matches

        # Return unique only
        #return list(dict.fromkeys(matches))
        return [matches, m2[1]]

    # Wrapper for networking.get()
    # With cache handler
    def fetch(self, url, cache=True): 

        # Build cache_path
        signature = md5sum(url)
        cache_path = get_hackwp_dir() + "/" + get_domain(self.args.target) + ".cache/" + signature

        # Check for cache
        if cache and os.path.exists(cache_path):
#            print("cache: ", url)
            with open(cache_path, 'r') as f:
                resp = respObj(json.load(f))
                self.d.msg(f"C: ({resp.status_code})",url)
                return resp 

        else:
#            print("live: ", url)
            time.sleep(.0025)
            resp = self.n.get(url)
            self.d.msg(f"L: ({resp.status_code})",url)
            if resp is False:
                return False

            # Save to cache
            data = {
                'url': url,
                'status_code': resp.status_code,
                'text': resp.text,
                'headers': dict(resp.headers),
                'history': []
            }
            if resp.history:
                data['history'].append({
                    'status_code': resp.history[0].status_code,
                    'url': resp.history[0].url,
                })
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














