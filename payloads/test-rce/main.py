##
# HackWP needs to know what methods is required to use this
def get_methods():
    return ['RCE'] 

def get_instructions(method, args):
    if method == 'RCE':
        # If we have RCE. Return PHP code
        if args.pos:
            return args.pos
        else:
            return [
                "<?php echo 'Testing RCE 1'; ?>",
                "<?php echo 'Testing RCE 2'; ?>",
            ]
##
# Author of this payload
def get_author():
    return "@etragardh"

##
# Special thanks to:
def get_thanks():
    return False 
