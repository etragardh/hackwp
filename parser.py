import argparse
class hwp_parser:

    def create():

        parser = argparse.ArgumentParser(
            prog='HackWP',
            description='Utility to hack wordpress sites',
            epilog="Don't hack shit without permission! help in blueteamer discord"
        )
        parser.add_argument(
            '-y', '--version',
            action='store_true',
            help='Display version'
        )
        parser.add_argument(
            '-u', '--wp-user',
            help='The WP user_login or user_email'
        )
        parser.add_argument(
            '-m', '--method',
            help='Force specific attack method. RCE|LFI|RFI|SQLe|SQLr' 
        )

        parser.add_argument(
            '-p', '--wp-pass',
            help='The WP password that belongs to --wp-user'
        )
        parser.add_argument(
            '-s', '--session-extract',
            action='store_true',
            help="Extract session cookies (simulate stolen cookies/hijack session)"
        )
        parser.add_argument(
            '-n', '--auth',
            action='store_true',
            help="Send credentials with this request (stolen cookies/hijack session)"
        )
        parser.add_argument(
            '-z', '--scan',
            action='store_true',
            help="Scan the target for vulnerabilities exploitable by HackWP"
        )
        parser.add_argument(
            '--agressive',
            action='store_true',
            help="Agressive scanning might yield a lot of 404 in the victim log. That is something fail2ban might catch and ban"
        )

        parser.add_argument(
            '--purge-cache',
            action='store_true',
            help="Delete all cache (that belongs to target domain) before HackWP starts"
        )
        parser.add_argument(
            '--delay-req',
            help="Aggressive scanning performs over 15 000 requests, you might want to delay them. Add delay in ms"
        )
        parser.add_argument(
            '-v', '--verbose',
            action='store_true',
        )
        parser.add_argument(
            '-t', '--target',
            help='The target url, full url like this: https://domain.com'
        )
        parser.add_argument(
            '-a', '--attack',
            help='attack module'
        )
        parser.add_argument(
            '-e', '--exploit',
            help='exploit module'
        )
        parser.add_argument(
            '-x', '--payload',
            help='exploit module'
        )
        parser.add_argument(
            'pos', nargs='*'
        )

        return parser
