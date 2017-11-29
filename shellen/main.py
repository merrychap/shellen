# import opt.completer

import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.abspath(__file__), os.pardir)))

from opt.appearance import cprint

from shellen import Shellen


def main():
    shell = Shellen()

    cprint(('<magenta>[*]</> You can type <white, bold>help</> to see the list of available commands.\n'
            '<magenta>[*]</> Also, to close this session you should enter <white,bold>q</> or <white,bold>quit</>\n'))
    
    shell.irun()


if __name__ == '__main__':
    main()