import readline


class IshellCompleter:
    def __init__(self, options):
        self.options = sorted(options)

    def complete(self, text, state):
        if state == 0:
            if text:
                self.matches = [s for s in self.options 
                                    if s and s.startswith(text)]
            else:
                self.matches = self.options[:]
        try: 
            return self.matches[state]
        except IndexError:
            return None


ishellcompleter = IshellCompleter(['asm', 'dsm'])
readline.set_completer(ishellcompleter.complete)
readline.parse_and_bind('tab: complete')