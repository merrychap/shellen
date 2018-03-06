from os import path

from setuptools import setup, find_packages, Extension


here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

shellen_module = Extension(
    'shellen_native',
    sources=['./ext/shellen.c']
)

setup(
    name='shellen',
    version='0.2.2',
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
    keywords=['shellcode', 'pwn', 'assembler', 'disassembler', 'syscalls'],
    packages=['shellen', 'shellen/opt', 'shellen/asms', 'shellen/syscalls'],
    include_package_data=True,
    package_data={'shellen/syscalls':['linux_tables/*.json']},
    install_requires=['keystone-engine', 'capstone', 'colorama', 'termcolor', 'terminaltables', 'prompt_toolkit', 'requests', 'pygments'],
    python_requires='>=3',
    entry_points={
        'console_scripts': [
            'shellen = shellen.main:main',
        ]
    },
    ext_modules=[shellen_module]
)
