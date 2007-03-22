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
OBJS     = nsauthpam.o

MODLIBS	 = -lpam

include  $(NAVISERVER)/include/Makefile.module
