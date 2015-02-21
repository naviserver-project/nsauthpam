ifndef NAVISERVER
    NAVISERVER  = /usr/local/ns
endif

#
# Module name
#
MOD      =  nsauthpam.so

#
# Objects to build.
#
MODOBJS     = nsauthpam.o

MODLIBS	 = -lpam

include  $(NAVISERVER)/include/Makefile.module
