import os

##
# Dependency
# What dependency does this payload have
def get_methods():
    return ['RFI']

##
# Detonate payload
# Return the code to execut
# or the file path to be uploaded
def get_instructions(method, args):
    if method == 'RFI':
        # If we have Remote File inclusion
        # Return the file path of mfb.php
        return [os.path.dirname(os.path.realpath(__file__)) + '/mfb.php']

##
# Author of this payload
def get_author():
    return "@etragardh"

##
# Special thanks to:
def get_thanks():
    return "@Smitka"
