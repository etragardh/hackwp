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
    return ['RCE']

##
# Detonate payload
# Return the code to execut
# or the file path to be uploaded
def detonate(vuln):
    if vuln == 'RCE':
        # If we have RCE. Return PHP code
        return [
            "<?php echo 'Testing RCE 1'; ?>",
            "<?php echo 'Testing RCE 2'; ?>",
        ]
