from os import path

from setuptools import setup, find_packages


here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()


setup(
    name='shellen',
    version='0.0.11',
    description='Interactive environment for crafting shellcodes. Also, it just can be used as a simple assembler/disassembler',
    long_description=long_description,
    url='https://github.com/merrychap/shellen',
    author='Mike Evdokimov',
    author_email='merrychap.c@gmail.com',
    license='MIT',
    classifiers = [
        'Environment :: Console',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Security',
        'Topic :: Software Development :: Disassemblers',
        'Topic :: Software Development :: Assemblers',
        'Topic :: System :: Shells',
        'Topic :: Utilities',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Intended Audience :: Information Technology'
    ],
    keywords=['shellcode', 'pwn', 'assembler', 'disassembler'],
    packages=['shellen', 'shellen/opt', 'shellen/asms'],
    install_requires=['keystone-engine', 'capstone', 'colorama', 'termcolor', 'terminaltables'],
    python_requires='>=3',
    entry_points={
        'console_scripts': [
            'shellen = shellen.main:main',
        ]
    }
)