from os import system
from pathlib import Path


sources = []
for pth in Path('slhdsa').glob('**/*.py'):
    if pth.name!='__init__.py':
        sources.append(pth.as_posix().replace('/', '\\'))
system(' '.join(['mypyc']+sources))