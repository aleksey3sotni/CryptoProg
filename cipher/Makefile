CXX = g++
CXXFLAGS = -Wall -I/usr/include/crypto++
LDFLAGS = -L/usr/lib/x86_64-linux-gnu -lcryptopp

TARGET = hash_program
SRCS = cipher.cpp

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)

clean:
	rm -f $(TARGET)
