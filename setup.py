#!/usr/bin/env python

import glob
import os
from pathlib import Path
import sys

if sys.version_info < (3, 9, 0):
    sys.stderr.write("ERROR: You need Python 3.9 or later to use slh-dsa yet.\n")
    exit(1)

from setuptools import Extension, find_packages, setup

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


if os.getenv('SLHDSA_BUILD_OPTIMIZED', '1') == '1':
    mypyc_targets = []
    print('Building Optimized Library')
    
    for pth in Path('slhdsa').glob('**/*.py'):
        if pth.name != '__init__.py':
            mypyc_targets.append(pth.as_posix().replace('/', os.sep))

    from mypyc.build import mypycify
    
    ext_modules = mypycify(
        mypyc_targets,
        opt_level = "3",
        debug_level = "1"
    )
else:
    ext_modules = []


metadata = tomllib.load(open('pyproject.toml', 'rb'))['project']
setup(
    name = "slhdsa",
    version = metadata['version'],
    description = metadata['description'],
    long_description = open('README.md', encoding='utf8').read(),
    author = metadata["authors"][0]["name"],
    author_email = metadata["authors"][0]["email"],
    url = metadata["urls"]["Homepage"],
    license = metadata["license"],
    py_modules = [],
    ext_modules = ext_modules,
    packages = find_packages(),
    classifiers = metadata["classifiers"],
    install_requires = metadata["dependencies"],
    python_requires = metadata["requires-python"],
    include_package_data = True,
    project_urls = metadata["urls"],
)