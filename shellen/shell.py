import os
import sys
import signal

import shellen_native as native

from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.shortcuts import prompt
from prompt_toolkit.styles import style_from_pygments, style_from_dict

from pygments.token import Token

from opt.appearance import cprint, make_colors

from archsconf import *

from asms.asm import AssemblerWrapper
from asms.disasm import DisassemblerWrapper

from syscalls.linux_handler import LinuxSysHandler

from fetcher import ShellStormFetcher

from base import CLI


ASM_MODE = 'asm'
DSM_MODE = 'dsm'

LINUX_OS   = 'linux'
WINDOWS_OS = 'windows'
MAC_OS     = 'macos'

LINUX_PROMPT   = 'L'
WINDOWS_PROMPT = 'W'
MACOS_PROMPT   = 'M'

OS_MATCHING = {
    LINUX_OS:   LINUX_PROMPT,
    WINDOWS_OS: WINDOWS_PROMPT,
    MAC_OS:     MACOS_PROMPT
}

INDENT = 25 * '='

DEFUALT_COUNT = 15


class Shellen(CLI):
    def __init__(self):
        super().__init__()

        # Assembler and disassembler instances
        self.__asm = AssemblerWrapper(X86_32)
        self.__dsm = DisassemblerWrapper(X86_32)

        # Syscalls handlers
        self.__linuxsys = LinuxSysHandler()

        # Shellcodes reciever
        self.__shellstorm = ShellStormFetcher()

        self.mode  = ASM_MODE
        self.os    = LINUX_OS
        self.pexec = self.__asm

        self.__prompt_init()

        self.__create_handlers()

    def execv(self, cmd):
        return self.pexec.perform(cmd)

    def last_shellcode(self):
        return self.pexec.last_shellcode()

    def __prompt_init(self):
        self.asm_history = InMemoryHistory()
        self.dsm_history = InMemoryHistory()

        self.prompt_style = style_from_dict({
            Token:       '#ff0066',
            Token.OS:    '#ff3838',
            Token.Colon: '#ffffff',
            Token.Mode:  '#f9a9c3 bold',
            Token.Arch:  '#5db2fc',
            Token.Pound: '#ffd82a',
        })

    def __get_history(self):
        if isinstance(self.pexec, AssemblerWrapper):
            return self.asm_history
        else:
            return self.dsm_history

    def prompt(self):
        def get_prompt_tokens(cli):
            return [
                (Token.OS,    OS_MATCHING[self.os]),
                (Token.Colon, ':'),
                (Token.Mode,  self.mode),
                (Token.Colon, ':'),
                (Token.Arch,  self.pexec.arch),
                (Token.Pound, ' > ')
            ]
        return prompt(get_prompt_tokens=get_prompt_tokens, style=self.prompt_style, history=self.__get_history())

    def __create_handlers(self):
        self.handlers = {
            (self.RHELP,    self.help),
            (self.RQUIT,    self.quit),
            (self.RASM,     self.asm),
            (self.RDSM,     self.dsm),
            (self.RARCHS,   self.archs),
            (self.RRUN,     self.run),
            (self.RSETARCH, self.setarch),
            (self.RCLEAR,   self.clear),
            (self.RSYSCALL, self.sys),
            (self.RSETOS,   self.setos),
            (self.RVSYS,    self.sysv),
            (self.RSHELL,   self.shell)
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
                cmd = self.prompt()
                if cmd == '':
                    continue
                else:
                    if not self.handle_command(cmd):
                        cprint('\n<red,bold>[-]</> Invalid command.\n')
            except Exception as e:
                cprint('\n<red,bold>[-]</> Error occured: {}\n'.format(e))
            except KeyboardInterrupt:
                cprint()

    def __get_arch(self):
        return self.pexec.executor.archname

    def help(self, *args):
        cprint((
            '\n<white,bold>PROMPT INFO</>\n'
            '   The get_colored_prompt format is <white,bold>OS</>:<white,bold>mode</>:<white,bold>arch</>\n'
            '       <white,bold>* OS</> is a current <white,underline>Operating System</>.\n'
            '           <white,bold>* L</> is <white,underline>Linux</>\n'
            '           <white,bold>* W</> is <white,underline>Windows</>\n'
            '           <white,bold>* M</> is <white,underline>MacOS</>\n'
            '       <white,bold>* mode</> is a current <white,underline>assembly mode</> (by default it\'s asm). See below for more information.\n'
            '       <white,bold>* arch</> is a chosen processor <white,underline>architecture</> (by default it\'s x86_32).\n'
            '\n<white,bold>BASIC</>\n'
            '   Basic commands are listed below:\n'
            '       <white,bold>* clear</>: Clear the terminal screen.\n'
            '       <white,bold>* help</>: Show this help message.\n'
            '       <white,bold>* quit, q, exit</>: Finish the current session and quit.\n'
            '\n<white,bold>MODES</>\n'
            '   If you want to change a current mode, then just type the name of a mode.\n'
            '   There are two assembly modes (each is described below):\n'
            '       <white,bold>* asm</>: Assembler mode.\n'
            '       <white,bold>* dsm</>: Disassembler mode.\n'
            '\n<white,bold>COMMON COMMANDS FOR MODES</>\n'
            '   Common commands can be used for both <white, underline>asm</> and <white, underline>dsm</> modes.\n'
            '       <white,bold>* archs</>: Print a table of available architectures for a current mode.\n'
            '       <white,bold>* run, r, go</>: Jump to the last shellcode in a subprocess. What could go wrong?\n'
            '                     Note that you don\'t get to control the base address your code gets loaded at,\n'
            '                     and this assumes that the instructions will make sense to your CPU.\n'
            '       <white,bold>* setarch [arch]</>: Change current processor architecture.\n'
            '       <white,bold>* setos [OS]</>: Change current operation system: <white,underline>windows/linux/macos</>.\n'
            '       <white,bold>* sys [pattern]</>: Search a syscall depending on OS, architecture and specified pattern.\n'
            '       <white,bold>* sysv [pattern]</>: It\'s <white,underline>sys</> command, but with verbose output.\n'
            '       <white,bold>* shell [keyword] [count]</>: List of shellcodes with URL that suit a given keyword.\n'
            '                                  [count] parameter can be <white,underline>ommited</>\n'
            '                                  This function requests shellcodes from http://shell-storm.org\n'
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
        cprint('\n' + self.pexec.archs() + '\n')

    def run(self):
        shellcode = self.last_shellcode()
        if not shellcode:
            cprint('\n<red,bold>[-]</> Assemble or disassemble something first!\n')
            return

        result = native.run(shellcode)
        if result < 0:
            sig_info = signal.Signals(-result)
            cprint('\n<red,bold>[-]</> Exited with signal <white>{}</> (<white,underline>{}</>)\n'.format(sig_info.name, sig_info.value))
        elif result == 0:
            cprint('\n<green>[+]</> Exited with status code 0.\n')
        else: # result > 0
            cprint('\n<yellow>[*]</> Exited with status code {}.\n'.format(result))

    def clear(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def setarch(self, arch):
        if not self.pexec.setarch(arch):
            cprint('\n<red,bold>[-]</> Incorrect architecture. Enter <white,bold>archs</> to see a list of available archs.\n')
            return
        cprint('\n<green>[+]</> Architecture of <white,underline>{}</> changed to <white,underline>{}</>\n'.format(self.mode, arch))
        self.arch = arch

    def setos(self, ros):
        os = ros.lower()
        try:
            OS_MATCHING[os]
            self.os = os
            cprint('\n<green>[+]</> OS changed to {}.\n'.format(os))
        except KeyError:
            cprint('\n<red,bold>[-]</> There isn\'t such OS.\n')

    def sys(self, pattern, verbose=False):
        if self.os == LINUX_OS:
            cprint('\n' + self.__linuxsys.get_printable_table(self.__get_arch(), pattern, colored=True, verbose=verbose) + '\n')

    def sysv(self, pattern):
        self.sys(pattern, verbose=True)

    def shell(self, pattern, count):
        count = count.strip()
        if count == '':
            count = DEFUALT_COUNT
        else:
            count = int(count)
        cprint('\n' + self.__shellstorm.fetch_table(pattern, os=self.os, arch=self.__get_arch(), count=count).table + '\n')


