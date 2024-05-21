from scanner.crawler import hwpc
import re, json
from helpers import get_unique
from debug import hwpd

class hwpsu:

    def __init__(self, args):
        self.args = args
        self.crawler = hwpc(args)
        self.d = hwpd(args.debug)

    def get_users(self):
        users = []

        ##
        # Step n - REST API
        # http://localhost/wp-json/wp/v2/users
        self.d.msg("Users: wp-json")
        uri = "/wp-json/wp/v2/users"
        url = self.args.target + uri
        resp = self.crawler.fetch(url)
        users_json = json.loads(resp.text)

        if users_json is not False:
            for user_data in users_json:
                self.d.msg("Adding user:", user_data['slug'])
                users.append(user_data['slug'])

        ##
        # Step n - Crawl site
        #        - oembedd info

        # Grab all oembed urls
        self.d.msg("Users: oembed")
        pattern = f'href="((.*?)\/oembed\/(.*?))("|\')'
        matches = self.crawler.crawl(self.args.target, pattern, 1, [])
        # Unique only
        matches = get_unique(matches)

        for match in matches:
            pattern = f'author_name":"(.*?)",'
            author = self.crawler.rfetch(match, pattern)
            users.append(author[0])
            self.d.msg("Adding user:", author[0])

        ##
        # Step n - Crawl site
        #        - author links (*/author/emil)
        
        self.d.msg("Users: crawl site for links")
        pattern = f'\/author\/(.*?)("|\')'
        matches = self.crawler.crawl(self.args.target, pattern, 1, [])
        matches = get_unique(matches)
        if matches:
            self.d.msg("Adding users:", matches)

        users = users + matches if matches is not False else users

        ##
        # Scrape feeds

        # http://localhost/feed/
        # <dc:creator><![CDATA[emil]]></dc:creator>
        self.d.msg("Users: scape /feed")
        url = self.args.target + '/feed/'
        pattern = f'<dc:creator><!\[CDATA\[(.*?)\]\]><\/dc:creator>'
        matches = self.crawler.rfetch(url, pattern)
        matches = get_unique(matches)
        if matches:
            self.d.msg("Adding users:", matches)
        users = users + matches if matches is not False else users

        # http://localhost/feed/atom/
        # <author><name>emil</name>
        self.d.msg("Users: scape /feed/atom")
        url = self.args.target + "/feed/atom/"
        pattern = f'<author>((.|\n)*?)<name>(.*?)<\/name>'
        matches = self.crawler.rfetch(url, pattern, 3)
        matches = get_unique(matches)
        if matches:
            self.d.msg("Adding users:", matches)
        users = users + matches if matches is not False else users
        
        ##
        # Scrape sitemaps

        # http://localhost/wp-sitemap-users-1.xml
        # <url><loc>http://localhost/author/emil</loc></url>
        self.d.msg("Users: scape /wp-sitemap-users-1")
        url = self.args.target + '/wp-sitemap-users-1.xml'
        pattern = f'<url><loc>(.*)\/author\/(.*?)<\/loc>'
        matches = self.crawler.rfetch(url, pattern, 2)
        matches = get_unique(matches)
        if matches:
            self.d.msg("Adding users:", matches)
        users = users + matches if matches is not False else users

        # Yoast sitemap
        # http://localhost/author-sitemap.xml
        # <url><loc>http://localhost/author/emil</loc></url>
        self.d.msg("Users: scape /author-sitemap")
        url = self.args.target + '/author-sitemap.xml'
        pattern = f'<url>((.|\n)*?)<loc>(.*?)\/author\/(.*?)\/<\/loc>'
        matches = self.crawler.rfetch(url, pattern, 4)
        matches = get_unique(matches)
        if matches:
            self.d.msg("Adding users:", matches)
        users = users + matches if matches is not False else users


        ##
        # User ID Brute Force
        # FIXME: agressive can add more than 10 per found user

        self.d.msg("Users: ID Brute Force")
        ids = list(range(1, 10+1))
        for id in ids:
            resp = self.crawler.fetch(self.args.target + '/?author=' + str(id))
            if resp.status_code in [200, 301, 302]:
                patterns = [
                    'author\/(.*?)\/',
                    '<body class=["|\'].*?author-(.*?)[ "|\']',
                    'Posts by (.*?) Feed'
                ]
                for pattern in patterns:
                    try:
                        match = re.search(pattern, resp.text).group(1)
                        #FIXME: save ID of the user as well
                        self.d.msg("Adding user:", match)
                        users.append(match)
                        r = range(ids[-1]+1, ids[-1]+11)
                        ids.extend(r)
                        break

                    except:
                        pass

            # Dont get more than 1000 users/tries
            if id >= 1000:
                break

        # TODO: enumerate emails

        # FIXME: return dict with info
        return get_unique(users) 

        ## When we have a list of users,
        ## we can chech against:
        ## http://localhost/author/emil/feed/
        ## or:
        ## http://localhost/wp-json/wp/v2/posts?author=1
        ## that will display all post created by this user
        ##
        ##
        # Step n - Crawl site
        #        - twitter links: (look for label written by)
        #<meta name="twitter:label1" content="Skriven av" />
        #<meta name="twitter:data1" content="tcm_emil" />
        #<meta name="twitter:label1" content="Time to read" />
        #<meta name="twitter:data1" content="Less than a minute" />
        #<meta name="twitter:label1" content="Written by" />
        #<meta name="twitter:data1" content="Kevin Geary" />
        #<meta name="twitter:label2" content="Time to read" />
        #<meta name="twitter:data2" content="Less than a minute" />
        # it can change from page to page on same website.
        # label1 says what data1 is holding etc.

        # login_error_messages

