from baseexc import BaseExec, BaseExecWrapper
from archsconf import *

from capstone import *


class Disassembler(BaseExec):
    def __init__(self):
        self.init_archs()

        self.arch = self.__archs[X86_32]
        self.__cs = Cs(*self.arch)
        
        self.baseaddr = 0x00080000

    # def test(self):
        # TODO remove this function
        # for i in self.__cs.disasm(b'\x89\xd0\x40', 0):
            # print("0x%08x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

    def init_archs(self):
        ''' Initialize the dictionary of architectures for disassembling via capstone'''

        self.__archs = {
            X86_16:  (CS_ARCH_X86,   CS_MODE_16),
            X86_32:  (CS_ARCH_X86,   CS_MODE_32),
            X64_64:  (CS_ARCH_X86,   CS_MODE_64),
            ARM32:   (CS_ARCH_ARM,   CS_MODE_ARM),
            ARM64:   (CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN),
            ARM_TB:  (CS_ARCH_ARM,   CS_MODE_THUMB),
            MIPS32:  (CS_ARCH_MIPS,  CS_MODE_MIPS32),
            MIPS64:  (CS_ARCH_MIPS,  CS_MODE_MIPS64),
            SPARC32: (CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN),
            SPARC64: (CS_ARCH_SPARC, CS_MODE_V9),
            SYSTEMZ: (CS_ARCH_SYSZ,  CS_MODE_BIG_ENDIAN),
        }

    def exec(self, data):
        return self.__cs.disasm(data, self.baseaddr)


class DisassemblerWrapper(BaseExecWrapper):
    def __init__(self):
        self.executor = Disassembler()

    def print_res(self, res):
        pass