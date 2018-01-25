import json

from opt.appearance import make_colors

from os import listdir
from os.path import join, isfile, splitext

from difflib import SequenceMatcher

from terminaltables import SingleTable, DoubleTable


EMPTY_VALUE = '-'

NAME_FIELD  = 'name'
DEF_FIELD   = 'definition'
ID_FIELD    = 'id'

NO_MATCHES_ERROR = '<red,bold>[-]</> No matches. Try again!'


class SysHandler:
    def __init__(self):
        self.tables         = {}
        self.req_similarity = 0.75

        self.tcache = {}

    def get_printable_table(self, arch, pattern, colored=False, verbose=False):
        table = self.get_table(arch, pattern, colored, verbose)
        return table.table if table is not None else NO_MATCHES_ERROR

    def get_table(self, arch, pattern, colored=False, verbose=False):
        '''
        This function is used in sys command (when user want to find a specific syscall)

        :param Architecture for syscall table;
        :param Searching pattern;
        :param Flag for verbose output
        :return Return a printable table of matched syscalls
        '''

        rawtable = self.search(arch, pattern)
        if len(rawtable) == 0:
            return None

        used_hd = self.__fetch_used_headers(rawtable, verbose)
        table   = [self.__make_colored_row(used_hd, 'yellow,bold', upper=True) if colored else used_hd]

        for command in rawtable:
            cur_tb_field = []
            for hd in used_hd:
                value = command[hd]
                cur_tb_field.append(self.__make_colored_field(value, hd, verbose=verbose))
            table.append(cur_tb_field)
        return DoubleTable(table)

    def __make_colored_field(self, field, hd, verbose=False):
        if hd == NAME_FIELD:
            return make_colors('<red>{}</>'.format(field))
        elif self.__is_number(field):
            return make_colors('<green>{}</>'.format(field))
        else:
            parts = field.split(' ')
            if verbose:
                return make_colors('<magenta>{}</> <white,bold>{}</>'.format(' '.join(parts[:-1]), parts[-1]))
            else:
                return make_colors('<white,bold>{}</>'.format(parts[-1]))

    def __is_number(self, s, base=16):
        try:
            int(s, base)
            return True
        except Exception:
            return False

    def __make_colored_row(self, row, pcolor, upper=False):
        return [make_colors('<{}>{}</>'.format(pcolor, val.upper() if upper else val)) for val in row]

    def __fetch_used_headers(self, table, verbose=False):
        def hdkey(hd):
            return -len(hd), hd.upper()

        used_hd = set()
        for command in table:
            for header, value in command.items():
                if value != EMPTY_VALUE:
                    used_hd.add(header)
        used_hd.remove(NAME_FIELD)
        used_hd.remove(DEF_FIELD)
        used_hd.remove(ID_FIELD)
        return [NAME_FIELD] + sorted(list(used_hd), key=hdkey) + ([DEF_FIELD] if verbose else [])

    def search(self, arch, pattern):
        try:
            table   = self.tables[arch]
            similar = []
            for command in table:
                if self.__similar(command['name'], pattern) >= self.req_similarity:
                    similar.append(command)
            return similar
        except KeyError:
            return []

    def load_tables(self):
        for filename in listdir(self.dir):
            fileloc = join(self.dir, filename)
            name    = splitext(filename)[0]
            if isfile(fileloc):
                with open(fileloc, 'r') as tmpfile:
                    self.tables[name] = json.loads(tmpfile.read())

    def __similar(self, s, f):
        return SequenceMatcher(None, s, f).ratio()