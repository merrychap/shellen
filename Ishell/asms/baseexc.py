import re

from archsconf import *
from opt.appearance import cprint, make_colors

from terminaltables import SingleTable

from abc import ABC, abstractmethod


MN_INF = -100000


class BaseExec(ABC):
    def __init__(self):
        super().__init__()

        self._archs = self.avail_archs()

    def get_archs(self):
        return self._archs

    @abstractmethod
    def execv(self, data):
        pass

    @abstractmethod
    def avail_archs(self):
        pass


class BaseExecWrapper(ABC):
    def __init__(self, arch):
        super().__init__()

        self.arch = arch

        self.executor = None

    @abstractmethod
    def print_res(self, res):
        pass

    def perform(self, cmd):
        try:
            res = self.executor.execv(cmd)
            self.print_res(res)
            return True
        except Exception:
            return False

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
                filtered.append(['<red>{}</>'.format(x) for x in cur])
                cur = [archs[pos]]
        filtered.append(['<red>{}</>'.format(x) for x in cur])
        loc_max = max(loc_max, len(cur))
        
        table.append(['\r'] * len(filtered))
        for i in range(loc_max):
            cur_row = []
            for j in range(len(filtered)):
                cur_row.append('' if i >= len(filtered[j]) else make_colors(filtered[j][i]))
            table.append(cur_row)
        rtable = SingleTable(table)
        rtable.inner_heading_row_border = False
        return rtable.table

        
