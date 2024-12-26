ACLOCAL_AMFLAGS = -I m4
bin_PROGRAMS=ddos_detector_v2
AM_CXXFLAGS = -std=c++2a -pthread -O3
ddos_detector_v2_SOURCES=src/main.cpp src/adaptiveCusum.cpp src/ddosDetector.cpp src/ddosDetectorValue.cpp fields.c
ddos_detector_v2_LDADD=-lunirec -ltrap
AM_CPPFLAGS = -I$(top_srcdir)/include 
# Makefile.am
debug: clean
	$(MAKE) all CFLAGS='-g -O0 -DDEBUG' CPPFLAGS='-DDEBUG'
include ./aminclude.am
