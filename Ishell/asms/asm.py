from asms.baseexc import BaseExec, BaseExecWrapper
from archsconf import *

from keystone import *


class Assembler(BaseExec):
    def __init__(self, parch):
        super().__init__()

        self.init_archs()

        self.arch = self.__archs[parch]
        self.__ks = Ks(*self.arch)

    def init_archs(self):
        ''' Initialize the dictionary of architectures for assembling via keystone'''

        self.__archs = {
            X86_16:  (KS_ARCH_X86,     KS_MODE_16),
            X86_32:  (KS_ARCH_X86,     KS_MODE_32),
            X64_64:  (KS_ARCH_X86,     KS_MODE_64),
            ARM32:   (KS_ARCH_ARM,     KS_MODE_ARM),
            ARM64:   (KS_ARCH_ARM64,   KS_MODE_LITTLE_ENDIAN),
            ARM_TB:  (KS_ARCH_ARM,     KS_MODE_THUMB),
            MIPS32:  (KS_ARCH_MIPS,    KS_MODE_MIPS32),
            MIPS64:  (KS_ARCH_MIPS,    KS_MODE_MIPS64),
            HEXAGON: (KS_ARCH_HEXAGON, KS_MODE_BIG_ENDIAN),
            PPC32:   (KS_ARCH_PPC,     KS_MODE_PPC32),
            PPC64:   (KS_ARCH_PPC,     KS_MODE_PPC64),
            SPARC32: (KS_ARCH_SPARC,   KS_MODE_SPARC32),
            SPARC64: (KS_ARCH_SPARC,   KS_MODE_SPARC64),
            SYSTEMZ: (KS_ARCH_SYSTEMZ, KS_MODE_BIG_ENDIAN),
        }

    def execv(self, data):
        return self.__ks.asm(data)


class AssemblerWrapper(BaseExecWrapper):
    def __init__(self, arch):
        super().__init__(arch)

        self.executor = Assembler(self.arch)

    def print_res(self, res):
        print(res)

    def archs(self):
        pass
