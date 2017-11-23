from opt.appearance import cprint

from ishell import Ishell


def main():
    ish = Ishell()

    cprint('<magenta>[*]</> You can type <white, bold>help</> to see the list of available commands.\n')
    
    ish.irun()


if __name__ == '__main__':
    main()