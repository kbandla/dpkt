#!/usr/bin/env python

from distutils.core import setup
import dpkt

setup(name='dpkt',
      version=dpkt.__version__,
      author=dpkt.__author__,
      url=dpkt.__url__,
      description='dumb packet module',
      packages=[ 'dpkt' ])
