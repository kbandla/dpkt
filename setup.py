#!/usr/bin/env python

import os
import sys
from distutils.core import setup
import dpkt

if sys.argv[-1] == 'publish':
    os.system('python setup.py sdist upload')
    sys.exit()

readme = open('README.rst').read()

setup(name='dpkt',
      version=dpkt.__version__,
      author=dpkt.__author__,
      url=dpkt.__url__,
      description='dumb packet module',
      long_description = readme,
      packages=[ 'dpkt' ]
    )
