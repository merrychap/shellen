from abc import ABC, abstractmethod


class BaseExec(ABC):
    def __init__(self):
        super().__init__()

    @abstractmethod
    def exec(self, data):
        pass


class BaseExecWrapper(ABC):
    def __init__(self):
        super().__init__()

        self.executor = None

    @abstractmethod
    def print_res(self, res):
        pass

    @abstractmethod
    def do_exec(self, cmd):
        self.executor.exec(cmd)