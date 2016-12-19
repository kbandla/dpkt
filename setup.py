import os
import sys

try:
    from setuptools import setup, Command
except ImportError:
    from distutils.core import setup, Command

package_name = 'dpkt'
description = 'fast, simple packet creation / parsing, with definitions for the basic TCP/IP protocols'
readme = open('README.rst').read()
requirements = []

# PyPI Readme
long_description = open('README.rst').read()

# Pull in the package
package = __import__(package_name)
package_version = package.__version__
if "bdist_msi" in sys.argv:
    # The MSI build target does not support a 4 digit version, e.g. '1.2.3.4'
    # therefore we remove the last digit.
    package_version, _, _ = package_version.rpartition('.')

setup(name=package_name,
      version=package_version,
      author=package.__author__,
      author_email=package.__author_email__,
      url=package.__url__,
      description=description,
      long_description=long_description,
      packages=['dpkt'],
      install_requires=requirements,
      license='BSD',
      zip_safe=False,
      classifiers=[
          'Development Status :: 4 - Beta',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: BSD License',
          'Natural Language :: English',
          'Programming Language :: Python :: 2.6',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3.5',
          'Programming Language :: Python :: Implementation :: CPython',
          'Programming Language :: Python :: Implementation :: PyPy',
      ]
)
