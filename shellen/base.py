import re


class CLI:
    def __init__(self):
        self.RCLEAR   = re.compile(r'^clear$')
        self.RHELP    = re.compile(r'^help$')
        self.RQUIT    = re.compile(r'^q$|^quit$|^exit$')
        self.RASM     = re.compile(r'^asm$')
        self.RDSM     = re.compile(r'^dsm$')
        self.RARCHS   = re.compile(r'^archs$')
        self.RRUN     = re.compile(r'^r$|^run$|^go$')
        self.RSETARCH = re.compile(r'^setarch[ ]+([\w\d]+?)$')
        self.RSYSCALL = re.compile(r'^sys[ ]+(.*?)$')
        self.RVSYS    = re.compile(r'^sysv[ ]+(.*?)$')
        self.RSETOS   = re.compile(r'^setos[ ]+(.*?)$')
        self.RSHELL   = re.compile(r'^shell[ ]+([^\s]*?)($|[ ]*\d*)$')
