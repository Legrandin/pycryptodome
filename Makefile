
PYTHON = /usr/bin/env python
CRYPTO_DIR = Crypto-1.1a2

all : source
	-ln -f Makefile.pre.in src/Makefile.pre.in
	# If the block/ directory is present, this must be the full
	# kit, not the suitable-for-export subset 
	if [ -d block ] ; then \
	  ln -f Setup.in src/Setup.in; \
	else \
	  ln -f Setup.in-export src/Setup.in; \
	fi
	(cd src ; make VERSION=1.5 -f Makefile.pre.in boot ; make)
#	mv src/python .

source :
	$(PYTHON) buildkit

clean : 
	-rm -f `find . -name '*~'` python
	-rm -f `find . -name '*.pyc'`
	-rm -f Demo/secimp/*.pys src/* Cipher/*.so Cipher/*.sl Hash/*.so Hash/*.sl
	-rm -f sedscript config.c
	-(cd Doc ; rm -f *.ps *.log *.aux *.ilg *.toc)
	-rm -f err out

install:
	cd src ; make install
	if [ -d block ] ; then \
	  cd src ; make cipherinstall; \
	fi 

test: 
	cd src ; make links
	python test.py --quiet

distrib : clean
	rm -f src/* 
#	python buildkit
#	cd Doc ; rm -f html/* ; texi2html pycrypt.texi html ; makeinfo pycrypt.texi 
	cd .. ; tar -cvf /scratch/pycrypt-export.tar -X $(CRYPTO_DIR)/not-for-export -X $(CRYPTO_DIR)/excludefiles $(CRYPTO_DIR) 
	cd .. ; tar -cvf /scratch/pycrypt-US.tar `cat $(CRYPTO_DIR)/not-for-export` -X $(CRYPTO_DIR)/excludefiles 
	cd Doc ; rm -f *.?? *.log *.aux *.ilg 

links:
	cd src ; make links
