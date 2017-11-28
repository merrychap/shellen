try:
    import readline
except Exception:
    pass

import sys

from opt.appearance import cprint

from archsconf import *

from asms.asm import AssemblerWrapper
from asms.disasm import DisassemblerWrapper

from cli import CLI


ASM_MODE = 'asm'
DSM_MODE = 'dsm'

INDENT = 25 * '='


class Ishell(CLI):
    def __init__(self):
        super().__init__()

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
        self.handlers = {
            (self.RHELP,    self.help),
            (self.RQUIT,    self.quit),
            (self.RASM,     self.asm),
            (self.RDSM,     self.dsm),
            (self.RARCHS,   self.archs),
            (self.RSETARCH, self.setarch)
        }

    def handle_command(self, command):
        for regex, handler in self.handlers:
            match = regex.match(command)
            if match:
                try:
                    handler(*match.groups())
                except Exception as e:
                    handler()
                return True
        return self.execv(command)

    def irun(self):
        while True:
            try:
                self.prompt()
                cmd = input(' ')

                if cmd == '':
                    continue
                else:
                    if not self.handle_command(cmd):
                        cprint('\n<red,bold>[-]</> Invalid command.\n')
            except Exception as e:
                cprint('\n<red,bold>[-]</> Error occured: {}\n'.format(e))
            except KeyboardInterrupt:
                cprint()

    def help(self, *args):
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

    def quit(self):
        cprint('\n\n<yellow>See you again!</>')
        sys.exit()

    def asm(self):
        self.mode  = ASM_MODE
        self.pexec = self.__asm
        cprint('\n<green>[+]</> Changed to <white,underline>asm</> (assembly) mode\n')

    def dsm(self):
        self.mode  = DSM_MODE
        self.pexec = self.__dsm
        cprint('\n<green>[+]</> Changed to <white,underline>dsm</> (disassembly) mode\n')

    def archs(self):
        cprint(self.pexec.archs())

    def setarch(self, arch):
        if not self.pexec.setarch(arch):
            cprint('<red,bold>[-]</> Incorrect architecture. Enter <white,bold>archs</> to see a list of available archs.')
            return
        self.arch = arch
