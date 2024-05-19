from networking import hwpn
from helpers import pinfo, pwarn, get_hackwp_dir, get_realpath, file_get_json, md5sum, get_domain
import os, requests, hashlib
from urllib.parse import urlparse
class hwpsc:

    def __init__(self, args):
        self.args = args

    ##
    # HackWP needs to know what version of WP Core
    # the target site is running
    # get all checksums for latest
    # get all checksums for 2nd to latest
    # get all checksums in latest, that are different
    # if there is just one single match, we know it is a HIT
    def get_version(self):
        versions = self.get_wp_core_versions()
        versions = list(versions)
        for i, version in enumerate(versions):

            # Fetch the changed files and checksums for this version
            checksums = self.get_wp_core_checksums(version, versions[i+1])

            total = 0
            matches = 0
            for file in checksums:

                # Only keep files that we can access remote
                if ".css" not in file and ".js" not in file:
                    continue

                wp_signature = checksums[file]
                target_signature = self.get_target_signature(file)

                # Skip if download did not succeed
                if target_signature == False:
                    continue

                total += 1
                if (target_signature == wp_signature):
                    matches += 1
                    #print("MATCH", file)
                else:
                    pass
                    #print("="*40)
                    #print("MISS", file)
                    #print(" -> (file)", md5sum(file))

                #print(" -> (wp)", wp_signature)
                #print(" -> (target)", target_signature)

#            print("Version check:", version)
#            print(" -> total", total)
#            print(" -> matches", matches)
#            print(" -> fails", total-matches)

            if total-matches <= 2 and total >= 3:
                return version

            total = 0
            matches = 0

        return False

    ##
    # Get target signature of specific file
    def get_target_signature(self, file):
        domain = get_domain(self.args.target)
        cache_path = get_hackwp_dir() + '/' + domain + '.cache/'
        
        # Create cache path
        if not os.path.exists(cache_path):
            os.mkdir(cache_path)

        # Return from cache if exists (these files dont change)
        if os.path.exists(cache_path + md5sum(file)):
            size = os.path.getsize(cache_path + md5sum(file))
            if int(size) >= 2000000:
                # We cannot handle hashes for too large files
                return False
            with open(cache_path + md5sum(file), 'r') as r:
                return md5sum(r.read())

        # Get file from remote
        n = hwpn(self.args)
        with n.get(self.args.target + '/' + file, stream=True) as r:
            #r.raise_for_status()
            if r.status_code != 200:
                return False
        
        # Save to cache
        with open(cache_path + md5sum(file), 'wb') as f:
            for chunk in r.iter_content(chunk_size=4096):
                # If you have chunk encoded response uncomment if
                # and set chunk_size parameter to None.
                #if chunk:
                f.write(chunk)

#        with n.get(self.args.target + '/' + file) as resp:
#            if resp.status_code != 200:
#                return False
#            hash = md5sum(resp.text)

        # Save hash to cache file
#        with open(cache_path + md5sum(file), 'w+') as f:
#            f.write(hash)

        size = os.path.getsize(cache_path + md5sum(file))
        if int(size) >= 2000000:
            # We cannot handle hashes for too large files
            return False
        with open(cache_path + md5sum(file), 'r') as r:
            return md5sum(r.read()) # its already hashed
#        return hash

    ##
    # Get a list of _all_ WP Core versions
    def get_wp_core_versions(self):
        versions        = file_get_json(get_realpath() + '/assets/scanner/wp.json')
        sorted_versions = dict(sorted(versions.items()))
        r_versions = reversed(sorted_versions)
       
        out = {}
        for v in r_versions:
            out.update({v:versions[v]})

        return out

    ##
    # Get _changed_ checksums for a specific version of WP Core
    # Changed is compared to the version that comes just before
    def get_wp_core_checksums(self, version, prev_version):
        this_path = get_realpath() + f'/assets/scanner/wp_{version}.json'
        prev_path = get_realpath() + f'/assets/scanner/wp_{prev_version}.json'
        
        if not os.path.exists(this_path):
            self.download_wp_core_checksums(version)

        if not os.path.exists(prev_path):
            self.download_wp_core_checksums(prev_version)

        this_json = file_get_json(this_path)['checksums']
        prev_json = file_get_json(prev_path)['checksums']

        out = {}

        for this_file in this_json:
            this_hash = this_json[this_file]
            prev_hash = prev_json[this_file] if this_file in prev_json else ""
            
            if this_hash != prev_hash:
                #print("changed:", this_file)
                out[this_file] = this_hash

            if this_file not in prev_json.keys():
                #print("new", this_file, this_hash)
                out[this_file] = this_hash

        return out

    ##
    # Download WP Core checksums for a specific version of WP Core
    def download_wp_core_checksums(self, version):
        path = get_realpath() + f'/assets/scanner/wp_{version}.json'
        if not os.path.exists(path):
            if self.args.verbose: pwarn("Downloading wp checksums: ", version)
            with requests.get(f'https://api.wordpress.org/core/checksums/1.0/?version={version}&locale=en_US') as r:
                with open(path, 'w+') as f:
                    f.write(r.text)

    def get_version_legacy(self):
        ## Not all of these are present in every installation


        ## / (self.html)
        ## <meta name="generator" content="WordPress 6.5.3" />
        ## wp-emoji-release.min.js?ver=6.5.3
        ## <link rel="stylesheet" id="wp-block-library-css" href="https://geary.co/wp-includes/css/dist/block-library/style.css?ver=6.5.3" media="all" />

        ## /wp-login.php
        ## <script src="http://localhost/wp-admin/js/password-strength-meter.min.js?ver=6.5.3" id="password-strength-meter-js"></script>

        ## /feed
        ## <generator>https://wordpress.org/?v=6.5.3</generator>

        ## 
        return "6.5.9"
