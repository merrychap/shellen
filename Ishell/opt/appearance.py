import re
import os


DEFAULT = 'white'

r_tag = re.compile(r'(<\w+>.*?</\w+>)')
r_group_tag = re.compile(r'<(\w+)>(.*?)</(\w+)>')


def printc(text='', end='\n'):
    text = str(text)
    stext = r_tag.split(text)
    for word in stext:
        match = r_group_tag.match(word)
        txt = word
        color = DEFAULT
        if match is not None:
            color_f = match.group(1)
            color_s = match.group(3)
            if color_f not in Colors.color or color_f != color_s:
                color = DEFAULT
            else:
                color = color_f
            txt = match.group(2)
        if os.name != 'nt':
            print(Colors.color[color] + txt + Colors.color[DEFAULT], end='')
        else:
            print(txt, end='')
    print(end=end)


class Colors:
    color = {
        'white': '\033[0m',
        'red': '\033[31m',
        'green': '\033[32m',
        'yellow': '\033[33m',
        'blue': '\033[34m',
        'purple': '\033[35m',
        'lred': '\033[1;31m',
        'lgreen': '\033[1;32m',
        'lyellow': '\033[1;33m',
        'lblue': '\033[1;34m',
        'lpurple': '\033[1;35m',
    }
