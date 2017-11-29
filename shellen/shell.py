try:
    import readline
except Exception:
    pass

import os
import sys

from opt.appearance import cprint

from archsconf import *

from asms.asm import AssemblerWrapper
from asms.disasm import DisassemblerWrapper

from cli import CLI


ASM_MODE = 'asm'
DSM_MODE = 'dsm'

INDENT = 25 * '='


class Shellen(CLI):
    def __init__(self):
        super().__init__()

        self.__asm = AssemblerWrapper(X86_32)
        self.__dsm = DisassemblerWrapper(X86_32)

        self.mode  = ASM_MODE
        self.pexec = self.__asm

        self.create_handlers()

    def execv(self, cmd):
        return self.pexec.perform(cmd)

    def prompt(self):
        cprint('<blue, bold>{}</>:<blue>{}</> <yellow,bold>></>'.format(self.mode, self.pexec.arch), end='')

    def create_handlers(self):
        self.handlers = {
            (self.RHELP,    self.help),
            (self.RQUIT,    self.quit),
            (self.RASM,     self.asm),
            (self.RDSM,     self.dsm),
            (self.RARCHS,   self.archs),
            (self.RSETARCH, self.setarch),
            (self.RCLEAR,   self.clear)
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
            '\n<white,bold>PROMPT INFO</>\n'
            '   The prompt format is <white,bold>mode</>:<white,bold>arch</>\n'
            '       <white,bold>• mode</> is a current <white,underline>assembly mode</> (by default it\'s asm). See below for more information.\n'
            '       <white,bold>• arch</> is a chosen processor <white,underline>architecture</> (by default it\'s x86_32).\n'
            '\n<white,bold>BASIC</>\n'
            '   Basic commands are listed below:\n'
            '       <white,bold>• clear</>: Clear the terminal screen.\n'
            '       <white,bold>• help</>: Show this help message.\n'
            '       <white,bold>• quit, q, exit</>: Finish the current session and quit.\n'
            '\n<white,bold>MODES</>\n'
            '   If you want to change a current mode, then just type the name of a mode.\n'
            '   There are two assembly modes (each is described below):\n'
            '       <white,bold>• asm</>: Assembler mode.\n'
            '       <white,bold>• dsm</>: Disassembler mode.\n'
            '\n<white,bold>COMMON COMMANDS FOR MODES</>\n'
            '   Common commands can be used for both <white, underline>asm</> and <white, underline>dsm</> modes.\n'
            '       <white,bold>• archs</>: Print a table of available architectures for a current mode.\n'
            '       <white,bold>• setarch [arch]</>: Change current processor architecture.\n'
            '\n<white,bold>ASSEMBLY MODE</>\n'
            '   <white,bold>asm</> mode is intended for assembling instructions.\n'
            '   To assembly instuctions, write them separated by colons.\n'
            '   If your shellcode has a null bytes, then they will be highlighted after assembling.\n'
            '   Remember to use appropriate <white,bold>arch</> for assembling!\n'
            '   <white,underline>Example of using</>:\n'
            '       asm:x86_32 > <white,bold>mov edx, eax; xor eax, eax; inc edx; int 80;</>\n'
            '          [+] Bytes count: 7\n'
            '              Raw bytes:  "\\x89\\xc2\\x31\\xc0\\x42\\xcd\\x50"\n'
            '              Hex string: "89c231c042cd50"\n'
            '\n<white,bold>DISASSEMBLY MODE</>\n'
            '   <white,bold>dsm</> mode allows you to disassembly bytes into instructions, based on the <white,bold>arch</>.\n'
            '   <white,underline>Example of using</>:\n'
            '       dsm:x86_32 > <white,bold>89c231c042cd50</>\n'
            '               0x00080000:     mov     edx, eax\n'
            '               0x00080002:     xor     eax, eax\n'
            '               0x00080004:     inc     edx\n'
            '               0x00080005:     int     0x50\n'
            '\n'
        ))

    def quit(self):
        cprint('\n\n<yellow>See you again!</>')
        sys.exit()

    def asm(self):
        if self.mode != ASM_MODE:
            self.mode  = ASM_MODE
            self.pexec = self.__asm
            cprint('\n<green>[+]</> Changed to <white,underline>asm</> (assembly) mode\n')

    def dsm(self):
        if self.mode != DSM_MODE:
            self.mode  = DSM_MODE
            self.pexec = self.__dsm
            cprint('\n<green>[+]</> Changed to <white,underline>dsm</> (disassembly) mode\n')

    def archs(self):
        cprint(self.pexec.archs())

    def clear(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def setarch(self, arch):
        if not self.pexec.setarch(arch):
            cprint('\n<red,bold>[-]</> Incorrect architecture. Enter <white,bold>archs</> to see a list of available archs.\n')
            return
        cprint('\n<green>[+]</> Architecture of <white,underline>{}</> changed to <white,underline>{}</>\n'.format(self.mode, arch))
        self.arch = arch
