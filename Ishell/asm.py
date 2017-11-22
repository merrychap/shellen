from keystone import *


class Assembler:
    def __init__(self):
        self.init_archs()

        self.__ks = Ks(KS_ARCH_X86, KS_MODE_32)

    def init_archs(self):
        ''' Initialize the dictionary of architectures for assembling via keystone'''

        self.__archs = {
            'x16':     (KS_ARCH_X86,     KS_MODE_16),
            'x86':     (KS_ARCH_X86,     KS_MODE_32),
            'x64':     (KS_ARCH_X86,     KS_MODE_64),
            'arm':     (KS_ARCH_ARM,     KS_MODE_ARM),
            'arm_t':   (KS_ARCH_ARM,     KS_MODE_THUMB),
            'arm64':   (KS_ARCH_ARM64,   KS_MODE_LITTLE_ENDIAN),
            'mips32':  (KS_ARCH_MIPS,    KS_MODE_MIPS32),
            'mips64':  (KS_ARCH_MIPS,    KS_MODE_MIPS64),
            'ppc32':   (KS_ARCH_PPC,     KS_MODE_PPC32),
            'ppc64':   (KS_ARCH_PPC,     KS_MODE_PPC64),
            'hexagon': (KS_ARCH_HEXAGON, KS_MODE_BIG_ENDIAN),
            'sparc':   (KS_ARCH_SPARC,   KS_MODE_SPARC32),
            'sparc64': (KS_ARCH_SPARC,   KS_MODE_SPARC64),
            'systemz': (KS_ARCH_SYSTEMZ, KS_MODE_BIG_ENDIAN)
        }

Assembler()