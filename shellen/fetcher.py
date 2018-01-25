import re
import requests

from archsconf import *

from opt.appearance import cprint, make_colors

from terminaltables import SingleTable, DoubleTable


SHELL_URL = 'http://shell-storm.org/api/?s={}'

PLATFORM = 'Sys'
TITLE    = 'Title'
URL      = 'URL'
LENGTH   = 'Length'

ARCH_MATCH = {
    X86_32:  'x86',
    X86_64:  'x86-64',
    ARM32:   'ARM',
    MIPS32:  'mips',
    PPC32:   'ppc',
    SPARC32: 'sparc'
}


class ShellStormFetcher:
    def __init__(self):
        self.rshell = re.compile(r'(.*?)::::(.*?)::::(.*?)::::(.*?)::::(.*?\n)')

    def fetch(self, pattern, os, arch, count, colored=False):
        table    = []
        cur_plat = '{}/{}'.format(os, self.arch2ss_arch(arch))

        resp  = requests.get(SHELL_URL.format(pattern)).text

        for row in self.rshell.findall(resp):
            author, platform, title, sid, url = row
            try:
                platform = platform.split('/')[0].lower() + '/' + platform.split('/')[1]
            except Exception:
                continue
            if platform == cur_plat:
                rtitle = title.split(' ')
                try:
                    int(rtitle[-2])
                    table.append([cur_plat, ' '.join(rtitle[:-3]), rtitle[-2], url])
                except Exception:
                    continue
        stable = table
        if colored:
            stable = self.__make_color_table(self.sort_rows(table, count))
        return [self.__get_colored_header([PLATFORM, TITLE, LENGTH, URL])] + stable

    def __get_colored_header(self, header):
        return [make_colors('<yellow,bold>{}</>'.format(x)) for x in header]

    def __make_color_table(self, table):
        ntable = []
        for row in table:
            ntable.append(self.__get_colored_row(row))
        return ntable

    def __get_colored_row(self, row):
        newrow = []
        newrow.append(make_colors('<red>{}</>'.format(row[0])))
        newrow.append(make_colors('<white,bold>{}</>'.format(row[1])))
        newrow.append(make_colors('<green>{}</>'.format(row[2])))
        newrow.append(make_colors('<cyan>{}</>'.format(row[3])))
        return newrow

    def fetch_table(self, pattern, os='linux', arch=X86_32, count=0):
        cprint('\n<magenta,bold>[*]</> Connecting to shell-storm.org...')
        rowtable = self.fetch(pattern, os, arch, count, True)
        return DoubleTable(rowtable)

    def sort_rows(self, table, count):
        def bytes_len(row):
            return int(row[2])
        return sorted(table, key=bytes_len)[:count]

    def arch2ss_arch(self, arch):
        return ARCH_MATCH[arch]