import os
from os.path import join

from syscalls.base_handler import SysHandler


class LinuxSysHandler(SysHandler):
    def __init__(self):
        super().__init__()
        self.dir = join(os.path.dirname(os.path.realpath(__file__)), 'linux_tables')

        self.load_tables()