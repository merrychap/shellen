from opt.appearance import cprint

from asms.baseexc import BaseExec, BaseExecWrapper, hex2bytes
from archsconf import *

from keystone import *

from binascii import hexlify, unhexlify


NULLBYTE = '\\x00'


class Assembler(BaseExec):
    def __init__(self, parch):
        super().__init__()

        self.last_shellcode = None
        self.setarch(parch)

    def get_last_shellcode(self):
        return self.last_shellcode

    def avail_archs(self):
        ''' Initialize the dictionary of architectures for assembling via keystone'''

        return {
            ARM32:   (KS_ARCH_ARM,     KS_MODE_ARM),
            ARM64:   (KS_ARCH_ARM64,   KS_MODE_LITTLE_ENDIAN),
            ARM_TB:  (KS_ARCH_ARM,     KS_MODE_THUMB),
            HEXAGON: (KS_ARCH_HEXAGON, KS_MODE_BIG_ENDIAN),
            MIPS32:  (KS_ARCH_MIPS,    KS_MODE_MIPS32),
            MIPS64:  (KS_ARCH_MIPS,    KS_MODE_MIPS64),
            PPC32:   (KS_ARCH_PPC,     KS_MODE_PPC32),
            PPC64:   (KS_ARCH_PPC,     KS_MODE_PPC64),
            SPARC32: (KS_ARCH_SPARC,   KS_MODE_SPARC32),
            SPARC64: (KS_ARCH_SPARC,   KS_MODE_SPARC64),
            SYSTEMZ: (KS_ARCH_SYSTEMZ, KS_MODE_BIG_ENDIAN),
            X86_16:  (KS_ARCH_X86,     KS_MODE_16),
            X86_32:  (KS_ARCH_X86,     KS_MODE_32),
            X86_64:  (KS_ARCH_X86,     KS_MODE_64),
        }

    def update_engine(self):
        self.__ks = Ks(*self.arch)

    def execv(self, data):
        shellcode, num_instructions = self.__ks.asm(data)
        self.last_shellcode = bytes(shellcode)
        return (shellcode, num_instructions)


class AssemblerWrapper(BaseExecWrapper):
    def __init__(self, arch):
        super().__init__(arch)

        self.executor = Assembler(self.arch)

    def __decorate_shellcode(self, sc, pbytes=True):
        cld_sc = ''
        offset = 4 if pbytes else 2
        for pos in range(0, len(sc), offset):
            _byte = sc[pos:pos+offset]
            if _byte == (NULLBYTE if pbytes else NULLBYTE[2:]):
                cld_sc += '<red,bold>' + _byte + '</>'
            else:
                cld_sc += '<white,bold>' + _byte + '</>'
        return cld_sc


    def print_res(self, res):
        encoding, count = res
        
        raw_hex   = hexlify(bytearray(encoding)).decode('utf-8')
        raw_bytes = hex2bytes(raw_hex)

        dec_sc_bytes = self.__decorate_shellcode(raw_bytes)
        dec_sc_hex   = self.__decorate_shellcode(raw_hex, False)

        is_zeroed = NULLBYTE in raw_bytes
        
        prefix = ''
        if is_zeroed:
            prefix += '   <yellow,bold>[!]</> Warning! Your shellcode contains <white,underline>null bytes</>!\n'
        cprint(prefix + (
            '   <green,bold>[+]</> Bytes count: <white,bold>{}</>\n'
            '       Raw bytes:  "{}"\n'
            '       Hex string: "{}"\n'
        ).format(len(encoding), dec_sc_bytes, dec_sc_hex))
        
