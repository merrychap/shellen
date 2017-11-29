from setuptools import setup, find_packages

setup(
    name='shellen',
    version='0.0.5',
    description='Interactive environment for crafting shellcodes. Or it just can be used as a simple assembler/disassembler',
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
    packages=['shellen', 'shellen/asms', 'shellen/opt'],
    install_requires=['keystone-engine', 'capstone', 'colorama', 'termcolor', 'terminaltables'],
    python_requires='>=3',
    entry_points={
        'console_scripts': [
            'shellen = shellen.main:main',
        ]
    }
)