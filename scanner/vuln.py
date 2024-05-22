from helpers import psuccess, pwarn, perror, get_realpath
import json
from packaging.version import Version
class hwpv:

    def __init__(self, args):
        self.args = args
        self.db_path = get_realpath()+'/assets/scanner/vulnerabilities.json'
        self.wp_path = get_realpath()+'/assets/scanner/wp.json'

    def core(self, version):
        if version is False:
            psuccess('-> Status unknown')
            return

        with open(self.wp_path, 'r') as f:
            json_data = json.load(f)

            if version not in json_data:
                perror("-> Invalid")
                return

            if json_data[version] == 'latest':
                psuccess("-> Latest")
            if json_data[version] == 'outdated':
                pwarn("-> Outdated")
            if json_data[version] == 'insecure':
                perror("-> Insecure")

    def theme(self, slug, version):
        self.software(slug, version, 'theme')

    def plugin(self, slug, version):
        self.software(slug, version, 'plugin')

    def software(self, slug, version, stype='theme'):
        with open(self.db_path) as f:
            json_data = json.load(f)

            for vuln in json_data:
                if json_data[vuln]['software'][0]['type'] != stype:
                    continue
                if json_data[vuln]['software'][0]['slug'] != slug:
                    continue

                affected = json_data[vuln]['software'][0]['affected_versions']
                if self.is_affected(version, affected) is True:
                    perror('-> Vulnerable to:')
                    perror(' -->', json_data[vuln]['title'])
                elif self.is_affected(version, affected) == 'maybe':
                    pwarn('-> Maybe vulnerable to:')
                    pwarn(' -->', json_data[vuln]['title'])

    def is_affected(self, version, affected_versions):
        if version is False:
            return "maybe"

        for v in affected_versions:
            return Version(version) <= Version(affected_versions[v]['to_version'])

