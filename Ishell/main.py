from ishell import Ishell


def main():
    ish = Ishell()

    try:
        ish.irun()
    except KeyboardInterrupt:
        print('\nBye')
        return


if __name__ == '__main__':
    main()