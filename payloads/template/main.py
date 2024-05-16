##
# HackWP needs to know what methods is required to use this
def get_methods():
    return ['RCE', 'LFI', 'RFI', 'SQLe', 'SQLr']

##
# HackWP needs instructions based on how the payload works
# Se sample returns
def get_instructions(method, args):
    if method == 'RCE':
        if args.pos:
            return args.pos                     # Positional arguments
        else:
            return [
                "<?php echo 'Test RCE 1'; ?>",  # PHP code
                "<?php echo 'Test RCE 2'; ?>",  # Multiple executions
            ]
    elif method == 'LFI':
        return ['/etc/shadow']                  # File on target FS
    elif method == 'RFI':
        return ['./shell.php']                  # File relative to this dir
    elif method == 'SQLe':
        return ['INSERT INTO ...']              # SQL (read and write)
    elif method == 'SQLr':
        return ['SELECT * FROM ...']            # SQL (read only)

##
# Author of this payload
# You will be mentioned when some one using this payload
def get_author():
    return "@etragardh"

##
# Special thanks to:
# People who helped or people who created open source stuff you are using
# They will be mentioned when some one is using this payload
def get_thanks():
    return ['@Smitka', '@Renato']
