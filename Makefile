CC = g++
CXXFLAGS = -std=c++2b -Wall
LDFLAGS =
EXEC = dns
SOURCES = main.cpp
HEADERS = argparser.h dns.h udp.h types.h
OBJECTS = $(SOURCES:.cpp=.o)
TEST_SCRIPT = test_dns.py

.PHONY: all clean test

all: $(EXEC)

$(EXEC): $(OBJECTS)
	$(CC) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp $(HEADERS)
	$(CC) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(EXEC) $(OBJECTS)

test: ${EXEC}
	python3 $(TEST_SCRIPT)
