from helpers import pdebug

class hwpd:

    def __init__(self, debug=False):
        self.debug = debug

    def msg(self, message, obj='', obj2=''):
        if self.debug:
            pdebug(message, obj, obj2)
