import json

from os import listdir
from os.path import join, isfile, splitext

from difflib import SequenceMatcher


class SysHandler:
    def __init__(self):
        self.tables         = {}
        self.req_similarity = 0.7

    def get_table(self, arch, pattern, verbose=False):
        '''
        This function is used in sys command (when user want to find a specific syscall)

        :param Architecture for syscall table;
        :param Searching pattern;
        :param Flag for verbose output
        :return Return a printable table of matched syscalls
        '''

        rawtable = self.search(arch, pattern)

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