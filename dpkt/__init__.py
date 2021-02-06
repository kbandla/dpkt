"""fast, simple packet creation and parsing."""
__author__ = 'Various'
__author_email__ = ''
__license__ = 'BSD-3-Clause'
__url__ = 'https://github.com/kbandla/dpkt'
__version__ = '1.9.4'

from dpkt import aoe, ethernet, ip, ppp

aoe._mod_init()
ethernet._mod_init()
ip._mod_init()
ppp._mod_init()
