ITSLIB=$(HOME)/myprj/itslib
all: vdwreader

ifeq ($(D),)
OPT=-O3
else
OPT=-O0
endif

clean:
	$(RM) -r $(wildcard *.o) *.dSYM vdwreader

vdwreader: vdwreader.o stringutils.o

CXXFLAGS=-g -Wall -c $(OPT) -I $(ITSLIB)/include/itslib -D_UNIX -D_NO_RAPI -I /usr/local/opt/openssl/include -I . -std=c++17

# include CDEFS from make commandline
CXXFLAGS+=$(CDEFS) -MD

LDFLAGS+=-g -Wall -L/usr/local/opt/openssl/lib -std=c++17 -lcrypto -lz

vpath .cpp $(ITSLIB)/src .

%.o: $(ITSLIB)/src/%.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@ 

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(filter %.cpp,$^) -o $@ 

%: %.o
	$(CXX) $(LDFLAGS) $^ -o $@


install:
	cp ext2rd ~/bin/
