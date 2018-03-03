from opt.appearance import cprint

from asms.baseexc import BaseExec, BaseExecWrapper, hex2bytes
from archsconf import *

from capstone import *

from binascii import hexlify, unhexlify


class Disassembler(BaseExec):
    def __init__(self, parch):
        super().__init__()

        self.setarch(parch)

        self.baseaddr = 0x00080000
        self.last_shellcode = None

        self.update_engine()

    def get_last_shellcode(self):
        return self.last_shellcode

    def avail_archs(self):
        ''' Initialize the dictionary of architectures for disassembling via capstone'''

        return {
            ARM32:   (CS_ARCH_ARM,   CS_MODE_ARM),
            ARM64:   (CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN),
            ARM_TB:  (CS_ARCH_ARM,   CS_MODE_THUMB),
            MIPS32:  (CS_ARCH_MIPS,  CS_MODE_MIPS32),
            MIPS64:  (CS_ARCH_MIPS,  CS_MODE_MIPS64),
            SPARC32: (CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN),
            SPARC64: (CS_ARCH_SPARC, CS_MODE_V9),
            SYSTEMZ: (CS_ARCH_SYSZ,  CS_MODE_BIG_ENDIAN),
            X86_16:  (CS_ARCH_X86,   CS_MODE_16),
            X86_32:  (CS_ARCH_X86,   CS_MODE_32),
            X86_64:  (CS_ARCH_X86,   CS_MODE_64),
        }

    def update_engine(self):
        self.__cs = Cs(*self.arch)

    def __parse_bytes(self, data):
        data = data.replace('\\x', '')
        if data[0] == data[-1] and data[0] in ["'", '"']:
            data = data[1:-1]
        return data

    def execv(self, data):
        unhexed = unhexlify(self.__parse_bytes(data))
        disassembled = self.__cs.disasm(unhexed, self.baseaddr)
        self.last_shellcode = bytes(unhexed)
        return disassembled


class DisassemblerWrapper(BaseExecWrapper):
    def __init__(self, arch):
        super().__init__(arch)

        self.executor = Disassembler(self.arch)

    def print_res(self, res):
        for line in res:
            cprint("\t<cyan>0x{:08X}</>:\t<yellow,bold>{:<8}</><white,bold>{}</>".format(line.address, line.mnemonic, line.op_str))
        cprint('\n')
