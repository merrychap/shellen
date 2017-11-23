from archsconf import *

from abc import ABC, abstractmethod


class BaseExec(ABC):
    def __init__(self):
        super().__init__()

    @abstractmethod
    def execv(self, data):
        pass


class BaseExecWrapper(ABC):
    def __init__(self, arch):
        super().__init__()

        self.arch = arch

        self.executor = None
        self.__result = ''

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

    def archs(self):
        pass