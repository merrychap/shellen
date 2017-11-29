import re
import os

from colorama import init
from termcolor import colored


init()

rtopen = re.compile(r'<([^/].+?)>')
rtclos = re.compile(r'</>')


class ColoredException(Exception):
    pass


def parse_text(text):
    parsed = []
    in_tag      = False
    inner_text  = ''
    for i in range(len(text)):
        if text[i] == '<' and not in_tag:
            in_tag = True
            parsed.append(inner_text)
            inner_text = '<'
        elif text[i] == '>' and in_tag:
            in_tag = False
            parsed.append(inner_text + '>')
            inner_text = ''
        else:
            inner_text += text[i]
    return list(filter(None, parsed + [inner_text]))


def apply_colors(pd_text):
    tag  = []
    text = ''

    for pos in range(len(pd_text)):
        part = pd_text[pos]

        opn = rtopen.findall(part)
        cls = rtclos.findall(part)

        if len(opn) != 0:
            try:
                tag = list(filter(None, [x.strip() for x in opn[0].split(',')]))
                pd_text[pos] = ''
            except KeyError:
                raise ColoredException('Some errors in your tag')
        elif len(cls) != 0:
            if len(tag) == 0:
                raise ColoredException('You don\'t have any open tag for the close tag')
            try:
                pd_text[pos-1] = Colored.apply(tag[0], tag[1:], text)
                pd_text[pos]   = ''
                
                tag = []
            except Exception:
                raise ColoredException('Incorrect values in tag')
        else:
            text = part
    return ''.join(pd_text)


def make_colors(text):
    return apply_colors(parse_text(text))


def cprint(text='', end='\n'):
    colored_text = make_colors(text)
    print(colored_text, end=end)


class Colored:
    colors = {'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white'}
    hights = {'on_red', 'on_green', 'on_yellow', 'on_blue', 'on_magenta', 'on_cyan', 'on_white'}
    attrs  = {'bold', 'dark', 'underline', 'blink', 'reverse', 'concealed'}

    def apply(color, attrs, text):
        return colored(text, color, attrs=attrs)