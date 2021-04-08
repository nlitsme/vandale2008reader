ITSLIB=$(HOME)/myprj/itslib
all: vdwreader

cmake:
	cmake -B build . $(if $(D),-DCMAKE_BUILD_TYPE=Debug,-DCMAKE_BUILD_TYPE=Release) $(CMAKEARGS)
	$(MAKE) -C build $(if $(V),VERBOSE=1)

clean:
	$(RM) -r $(wildcard *.o) *.dSYM vdwreader
	$(RM) -r build CMakeFiles CMakeCache.txt CMakeOutput.log

vdwreader: vdwreader.o stringutils.o

CFLAGS=-g -Wall $(if $(D),-O0,-O3)
CFLAGS+=-I $(ITSLIB)/include/itslib
CFLAGS+=-D_UNIX -D_NO_RAPI
CFLAGS+=-I /usr/local/opt/openssl/include
CFLAGS+=-I .

CXXFLAGS=-std=c++17

# include CDEFS from make commandline
CFLAGS+=$(CDEFS)

LDFLAGS+=-g -Wall -L/usr/local/opt/openssl/lib -lcrypto -lz

vpath .cpp $(ITSLIB)/src .

%.o: $(ITSLIB)/src/%.cpp
	$(CXX) -c $(CFLAGS) $(CXXFLAGS) $^ -o $@ 

%.o: %.cpp
	$(CXX) -c $(CFLAGS) $(CXXFLAGS) $(filter %.cpp,$^) -o $@ 

%: %.o
	$(CXX) $(LDFLAGS) $^ -o $@

