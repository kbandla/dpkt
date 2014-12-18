import os
import sys

try:
    from setuptools import setup, Command
except ImportError:
    from distutils.core import setup, Command

package_name = 'dpkt'
description = 'dumb packet processing python module'
readme = open('README.rst').read()
requirements = [ 
]

# Pull in the package
package = __import__(package_name)

# Publish to PyPI
if sys.argv[-1] == 'publish':
    os.system('python setup.py sdist upload')
    sys.exit()

setup(name=package_name,
    version=package.__version__,
    author=package.__author__,
    url=package.__url__,
    description=description,
    packages=['dpkt'],
    install_requires=requirements,
    zip_safe=False,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Programming Language :: Python :: 2.7'
    ]
)
