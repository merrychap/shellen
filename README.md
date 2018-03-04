# Shellen

## General
Shellen is an interactive shellcoding environment. If you want a handy tool to write shellcodes, then shellen may be your friend. Shellen can also be used as an assembly or disassembly tool.

[keystone](https://github.com/keystone-engine/keystone) and [capstone](https://github.com/aquynh/capstone) engines are used for all of shellen's operations.

Shellen **only works on python3**. python2 support may appear in the future.

## Installing
First, you should install shellen's dependencies:
```sh
$ sudo apt-get install cmake python3-dev python3-setuptools
```

You can install the stable version of shellen using ```pip3```:
```sh
$ sudo pip3 install shellen
```

Or if you already have all required packages (see [Requirements](#requirements)):
```sh
$ python3 setup.py install
```

If you have any problems with installing keystone-engine, then you should compile keystone-engine (see the [COMPILE.md](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE.md) file in the [keystone](https://github.com/keystone-engine/keystone) repository)

## How to Run Shellen
After installing shellen and its required packages, you can run shellen by typing the following in your terminal:
```sh
$ shellen
```
You can run shellen's ```help``` command to get information about shellen's usage.

## Shellen's Features
Shellen assembles and disassembles instructions, so there are two usage modes: **asm** and **dsm** respectively. There are other features which include searching syscall tables and searching for common shellcodes.

### Prompt
Shellen has a useful prompt that displays the current mode, OS (operating system for syscalls), and the current mode's chosen architecture. Shellen's prompt looks like this:
```sh
L:asm:x86_32 >
```
You can edit your input like you're typing in a terminal. Also, shellen records your command history (just type your up arrow to see your previous commands).

```L``` is the shortened name of ```Linux``` in the prompt. Below listed all other OS names:
- ```L``` is Linux
- ```W``` is Windows
- ```M``` is MacOS

If you want to change OS, then type ```setos [linux/windows/macos]``` as follows:
```sh
L:asm:x86_32 > setos windows

[+] OS changed to windows.
```


To change current mode, enter ```asm``` or ```dsm``` in the prompt.
```sh
L:dsm:arm32 > asm

[+] Changed to asm (assembly) mode

L:asm:x86_32 > dsm

[+] Changed to dsm (disassembly) mode

L:dsm:arm32 > 
```

### Base Commands
Command | Description
------- | -----------
```clear``` | Clear the terminal screen. As usual ```cls``` on Windows or ```clear``` on *nix systems.
```help``` | Show the help message.
```quit,q,exit``` | Finish the current session and quit

### Assembling
To assemble instuctions, type them and separate them with semicolons as shown here:
```sh
L:asm:x86_32 > mov edx, eax; xor eax, eax; inc edx; int 80;
   [+] Bytes count: 7
       Raw bytes:  "\x89\xc2\x31\xc0\x42\xcd\x50"
       Hex string: "89c231c042cd50"
```
If your assembled bytes contain a null byte, then shellen will tell you about this.

### Disassembling
Disassembling is similar to assembling. Instead, type your bytes in the prompt and see the result!
```sh
L:dsm:x86_32 > 89c231c042cd50
        0x00080000:     mov     edx, eax
        0x00080002:     xor     eax, eax
        0x00080004:     inc     edx
        0x00080005:     int     0x50
```

### Run shellcode
Also, you can run your shellcode in a subprocess. **Be aware that this can harm your system!**. Jump to the last shellcode in a subprocess. What could go wrong?' Note that you don't get to control the base address your code gets loaded at, and this assumes that the instructions will make sense to your CPU. See ```help```inside ```shellen``` to see how to use it.

I'm planning to execute subprocess in a some virtual environment in order to make it safer to run potentially dangerous shellcode.

### Architectures
```asm``` and ```dsm``` modes work for different architectures. To see a list of available architectures for shellen's current mode, type this:
```sh
L:dsm:x86_32 > archs
┌────────┬────────┬─────────┬─────────┬────────┐
│        │        │         │         │        │
│ arm32  │ mips32 │ sparc32 │ systemz │ x86_16 │
│ arm64  │ mips64 │ sparc64 │         │ x86_32 │
│ arm_tb │        │         │         │ x86_64 │
└────────┴────────┴─────────┴─────────┴────────┘
```

If you want to change the current architecture, enter the following:
```sh
L:dsm:x86_32 > setarch arm32

[+] Architecture of dsm changed to arm32
```

### Syscalls
When you create a shellcode, you will need syscalls. To lookup syscalls with shellen, type ```sys```  and the name of your desired syscall. Shellen will produce a list of syscalls which may contain the syscall you were looking for.
```sh
L:asm:x86_32 > sys open

┌────────┬───────┬──────────────────────┬──────────────────────┬──────────────┬──────────────┐
│ name   │ eax   │ ebx                  │ ecx                  │ edx          │ esi          │
├────────┼───────┼──────────────────────┼──────────────────────┼──────────────┼──────────────┤
│ open   │ 0x05  │ const char *filename │ int flags            │ umode_t mode │ -            │
│ openat │ 0x127 │ int dfd              │ const char *filename │ int flags    │ umode_t mode │
└────────┴───────┴──────────────────────┴──────────────────────┴──────────────┴──────────────┘
```
``sys`` prints a list of possible variants for the provided syscall. The syscall table that shellen searches depends on the chosen architecture and operating system (OS). In this case, the architecture is ```x86_32``` and the OS is ```Linux```.


### Common Shellcodes
Shellen can show you a list of common shellcodes depending on your keyword. Shellen's keyword lookup uses shell-storm.org's API (thanks to the author!) and can be used like this:
```sh
L:asm:x86_32 > shell <keyword> <count>
```
Note, the ```count``` parameter isn't required. There is an image of ``shell <keyword> <count>``'s output in the [Pictures](#pictures) section.

### Supported Operating Systems
Currently, shellen is only supported on Linux. If you want to add functionality for Windows or MacOS, then write an issue and I will add support.

## How to Report Problems or Request for New Features
If you find a problem/bug or something, write an issue about this problem. Also, if you think that a feature will be a nice addition to shellen, do the same -- write an issue and I will try to add your requested feature.


## Requirements
- [keystone](https://github.com/keystone-engine/keystone)
- [capstone](https://github.com/aquynh/capstone)
- [colorama](https://github.com/tartley/colorama)
- [termcolor](https://pypi.python.org/pypi/termcolor)
- [terminaltables](https://github.com/Robpol86/terminaltables)

## TODO
- [x] Assembling
- [x] Disassembling
- [x] Syscalls lists
- [x] Database of common shellcodes
- [ ] Fix readline (right now it works ugly)
- [ ] Add ROP builder
- [ ] Add editing an assembly code in multiple lines

## Pictures
Just a little bunch of pictures. (They are outdated because of adding different features)

<p align="left">
  <img src="screens/help.png">
</p>
<hr>

<p align="left">
  <img src="screens/use.png">
</p>
<hr>

<p align="left">
  <img src="screens/syscalls.png">
</p>
<hr>

<p align="left">
  <img src="screens/shell.png">
</p>
<hr>

<p align="left">
  <img src="screens/tables.png">
</p>

