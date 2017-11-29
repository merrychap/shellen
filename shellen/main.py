# import opt.completer

from shell import Shellen

from opt.appearance import cprint


def main():
    shell = Shellen()

    cprint(('<magenta>[*]</> You can type <white, bold>help</> to see the list of available commands.\n'
            '<magenta>[*]</> Also, to close this session you should enter <white,bold>q</> or <white,bold>quit</>\n'))
    
    shell.irun()


if __name__ == '__main__':
    main()