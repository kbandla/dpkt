
Notes
======

PyPI Release How-To
-------------------
Notes and information on how to do the PyPI release for the dpkt project.

Package Requirements
~~~~~~~~~~~~~~~~~~~~

- pip install tox
- pip install wheel

Tox Background
~~~~~~~~~~~~~~
Tox will install the dpkt package into a blank virtualenv and then execute all the tests against the newly installed package. So if everything goes okay, you know the pypi package installed fine and the tests (which pull from the installed dpkt package) also ran okay.

Create the PyPI Release
~~~~~~~~~~~~~~~~~~~~~~~
.. code-block:: bash

 $ cd dpkt
 $ tox 
 $ vi dpkt/__init__.py and bump the version
 $ python setup.py release
   <enter your pypi password>

If everything above went okay...

.. code-block:: bash

 $ git add dpkt/__init__.py
 $ get commit -m "dpkt version 1.8.7 (or whatever)"
 $ git tag v1.8.7 (or whatever)
 $ git push --tags
 $ git push
 
Git Releases (discussion)
~~~~~~~~~~~~~~~~~~~~~~~~~
You can also do a 'release' on GitHub (the tags above are perfect for that). In general this is discouraged, people should always do a $pip install dpkt. If people want older releases they can do a $pip install dpkt==<old version>. Providing tarballs/zip file on GitHub will just confuse new users and they'll have a 'bad experience' when trying to deal with a tarball.

