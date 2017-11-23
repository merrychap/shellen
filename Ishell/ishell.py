import sys

from opt.appearance import cprint

from archsconf import *

from asms.asm import AssemblerWrapper
from asms.disasm import DisassemblerWrapper


ASM_MODE = 'asm'
DSM_MODE = 'dsm'

INDENT = 25 * '='


class Ishell:
    def __init__(self):
        self.create_handlers()

        self.arch  = X86_32

        self.__asm = AssemblerWrapper(self.arch)
        self.__dsm = DisassemblerWrapper(self.arch)

        self.mode = ASM_MODE

        self.pexec = self.__asm

    def execv(self, cmd):
        return self.execs[self.mode].perform(cmd)

    def prompt(self):
        cprint('<blue, bold>{}</>:<blue>{}</> <yellow,bold>></>'.format(self.mode, self.arch), end='')

    def create_handlers(self):
        def asm():
            self.mode  = ASM_MODE
            self.pexec = self.__asm
            cprint()
        
        def dsm():
            self.mode  = DSM_MODE
            self.pexec = self.__dsm
            cprint()

        self.__handlers = {
            'help':  self.help,
            'asm':   asm,
            'dsm':   dsm,
            'archs': 
        }

    def exit(self):
        cprint('\n\n<yellow>See you again!</>')
        sys.exit()

    def irun(self):
        while True:
            try:
                self.prompt()
                inp = input(' ')

                if inp == '':
                    continue
                elif inp in ['exit', 'q']:
                    self.exit()
                elif len(inp.split(' ')) == 1:
                    self.__handlers[inp]()
                else:
                    pass
                
            except Exception as e:
                cprint('<red,bold>[-]</> Error occured: {}'.format(e))
            except KeyboardInterrupt:
                self.exit()

    def help(self):
        cprint((
            '\n<white, bold>MODES</>'
            '\nYou can change current mode just by typing the name of a mode.\n'
            'There are two modes:\n'
            '\t<white,bold>asm</>: Assembler mode.\n'
            '\t<white,bold>dsm</>: Disassembler mode.\n'
            '\n'
        ))

    def archs(self):
        self.pexec.archs()
        