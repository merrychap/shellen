from asm import AssemblerWrapper
from disasm import DisassemblerWrapper


ASM_MODE = 'asm'
DSM_MODE = 'disasm'


class Ishell:
    def __init__(self):
        self._asm = AssemblerWrapper()
        self._dsm = DisassemblerWrapper()

        self.mode = ASM_MODE

    def exec(self, data):
        if self.mode == ASM_MODE:
            self._asm.exec(data)
        elif self.mode == DSM_MODE:
            self._dsm.exec(data)

    def prompt(self):
        return '{} > '.format(self.mode)

    def irun(self):
        while True:
            try:
                data = input(self.prompt())
                cmd = data.split(' ')[0]
            except Exception:
                print('[-] Incorrect command')
            

    def help(self):
        print((''))