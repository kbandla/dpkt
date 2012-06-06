# $Id: Makefile 345 2006-02-01 15:47:16Z dugsong $

PYTHON	= python
#BDIST_MPKG= bdist_mpkg
BDIST_MPKG= /System/Library/Frameworks/Python.framework/Versions/2.6/Extras/bin/bdist_mpkg
PKGDIR  = dpkt-`egrep version dpkt/__init__.py | cut -f2 -d"'"`
URL	= `egrep url dpkt/__init__.py | cut -f2 -d"'"`

all:
	$(PYTHON) setup.py build

install:
	$(PYTHON) setup.py install

test:
	$(PYTHON) test.py

doc:
	epydoc -o doc -n dpkt -u $(URL) --docformat=plaintext ./dpkt/

pkg_win32:
	$(PYTHON) setup.py bdist_wininst

pkg_osx:
	$(BDIST_MPKG) --readme=README --license=LICENSE
	PKGNAME=`basename dist/*.mpkg | sed s/\.mpkg//` ; \
	hdiutil create -srcfolder dist -volname $${PKGNAME} $${PKGNAME}.dmg

clean:
	rm -rf build dist doc *.dmg

cleandir distclean: clean
	rm -f *.pyc *~ */*.pyc */*~
