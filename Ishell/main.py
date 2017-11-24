# import opt.completer

from opt.appearance import cprint

from ishell import Ishell


def main():
    ish = Ishell()

    cprint(('<magenta>[*]</> You can type <white, bold>help</> to see the list of available commands.\n'
            '<magenta>[*]</> Also, to close this session you should type <white,bold>q</> or <white,bold>quit</>\n'))
    
    ish.irun()


if __name__ == '__main__':
    main()