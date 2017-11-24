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
        self.arch  = X86_32
        self.__asm = AssemblerWrapper(self.arch)
        self.__dsm = DisassemblerWrapper(self.arch)

        self.mode  = ASM_MODE
        self.pexec = self.__asm

        self.create_handlers()

    def execv(self, cmd):
        return self.pexec.perform(cmd)

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

        def archs():
            cprint(self.pexec.archs())

        self.__handlers = {
            'help':  self.help,
            'asm':   asm,
            'dsm':   dsm,
            'archs': archs
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
                elif inp in ['quit', 'q']:
                    self.exit()
                elif len(inp.split(' ')) == 1:
                    self.__handlers[inp]()
                else:
                    self.execv(inp)
                
            except Exception as e:
                cprint('<red,bold>[-]</> Error occured: {}'.format(e))
            except KeyboardInterrupt:
                # self.exit()
                cprint()

    def help(self):
        cprint((
            '\n<white, bold>PROMPT INFO</>\n'
            '   You can see a prompt format like <white,bold>mode</>:<white,bold>arch</>\n'
            '   Where <white,underline>mode</> is a current assembly mode (see below for more information)\n'
            '   And an <white,underline>arch</> is a chosen processor architecture.\n'
            '\n<white, bold>BASIC</>\n'
            '   Basic commands are listed below:\n'
            '       <white,bold>• help</>: Show this help message.\n'
            '       <white,bold>• quit, q</>: Finish the current session and quit.\n'
            '\n<white, bold>MODES</>'
            '\n   You can change current mode just by typing the name of a mode.\n'
            '   There are two modes:\n'
            '       <white,bold>• asm</>: Assembler mode.\n'
            '       <white,bold>• dsm</>: Disassembler mode.\n'
            '\n<white, bold>COMMON COMMANDS</>\n'
            '   This is common commands for both <white, underline>asm</> and <white, underline>dsm</> modes\n'
            '       <white,bold>• archs</>: Print a table of available architectures for a current mode\n'
            '\n'
            '\n'
        ))

    def archs(self):
        self.pexec.archs()
        