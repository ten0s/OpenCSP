CFLAGS := -g -O0 -I$(HOME)/projects/bee/install/include
LDFLAGS := -L$(HOME)/projects/bee/install/lib
WINEGCC := winegcc
WINEG++ := wineg++
MINGWCC := x86_64-w64-mingw32-gcc
WINDRES := x86_64-w64-mingw32-windres
WINEPREFIX ?= ~/.wine

MODULES = opencsp

all: $(MODULES)

opencsp: opencsp.cpp enumalgs.cpp hash.cpp
	$(WINEG++) $(CFLAGS) -shared -fPIC $^ $@.spec $(LDFLAGS) -lcrypto -lssl -o $@.dll.so

wine-install: opencsp
	cp -f opencsp.dll.so $(WINEPREFIX)/drive_c/windows/system32/
	wine64 reg import opencsp.reg

clean:
	rm -f *.dll *.res *.so
