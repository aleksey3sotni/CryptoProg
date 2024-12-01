CXX = g++
CXXFLAGS = -Wall -I/usr/include/crypto++  
LDFLAGS = -L/usr/lib/x86_64-linux-gnu -lcryptopp  

all: hasher

hasher: hasher.o
	$(CXX) -o hasher hasher.o $(LDFLAGS)

hasher.o: hasher.cpp
	$(CXX) $(CXXFLAGS) -c hasher.cpp

clean:
	rm -f hasher hasher.o
