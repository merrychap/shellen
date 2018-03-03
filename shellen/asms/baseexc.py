import re

from archsconf import *
from opt.appearance import cprint, make_colors

from terminaltables import SingleTable, AsciiTable, DoubleTable

from abc import ABC, abstractmethod


MN_INF = -100000


def hex2bytes(s):
    rbytes = ''
    for i in range(0, len(s), 2):
        hx = s[i:i+2]
        rbytes += '\\x' + hx
    return rbytes


class BaseExec(ABC):
    def __init__(self):
        super().__init__()

        self.arch     = (-1, -1)
        self.archname = 'none'
        self._archs   = self.avail_archs()

    def get_archs(self):
        return self._archs

    @abstractmethod
    def execv(self, data):
        pass

    @abstractmethod
    def avail_archs(self):
        pass

    @abstractmethod
    def update_engine(self, arch):
        pass

    def setarch(self, arch):
        self.archname = arch
        if arch in list(self.get_archs().keys()):
            self.arch = self._archs[arch]
            self.update_engine()
            return True
        else:
            return False


class BaseExecWrapper(ABC):
    def __init__(self, arch):
        super().__init__()

        self.arch = arch

        self.executor = None

    @abstractmethod
    def print_res(self, res):
        pass

    def setarch(self, arch):
        self.arch = arch
        return self.executor.setarch(arch)

    def perform(self, cmd):
        try:
            res = self.executor.execv(cmd)
            self.print_res(res)
            return True
        except Exception:
            return False

    def last_shellcode(self):
        return self.executor.get_last_shellcode()

    def __is_similar(self, s1, s2):
        pos = 0
        for pos in range(min(len(s1), len(s2))):
            if s1[pos] != s2[pos]:
                break
        return pos >= 3

    def archs(self):
        filtered = []
        table    = []
        
        archs = sorted(list(self.executor.get_archs()))

        cur     = [archs[0]]
        loc_max = MN_INF
        for pos in range(1, len(archs)):
            if self.__is_similar(archs[pos], archs[pos-1]):
                cur.append(archs[pos])
            else:
                loc_max = max(loc_max, len(cur))
                filtered.append(['<cyan>{}</>'.format(x) for x in cur])
                cur = [archs[pos]]
        filtered.append(['<cyan>{}</>'.format(x) for x in cur])
        loc_max = max(loc_max, len(cur))
        
        table.append(['\r'] * len(filtered))
        for i in range(loc_max):
            cur_row = []
            for j in range(len(filtered)):
                cur_row.append('' if i >= len(filtered[j]) else make_colors(filtered[j][i]))
            table.append(cur_row)
        rtable = DoubleTable(table)
        rtable.inner_heading_row_border = False
        return rtable.table

        
