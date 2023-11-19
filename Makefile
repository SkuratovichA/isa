CC = g++
CXXFLAGS = -std=c++20 -Wall
DEBUGFLAGS = -DDEBUG -g
LDFLAGS =
EXEC = dns
SRC_DIR = src
OBJ_DIR = object_files
SOURCES = $(SRC_DIR)/main.cpp
HEADERS = $(SRC_DIR)/argparser.h $(SRC_DIR)/dns.h $(SRC_DIR)/udp.h $(SRC_DIR)/types.h
OBJECTS = $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(SOURCES))
TEST_SCRIPT = test_dns.py

.PHONY: all clean test debug

all: $(EXEC)

$(EXEC): $(OBJECTS)
	$(CC) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp $(HEADERS)
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CXXFLAGS) -c $< -o $@

debug: CXXFLAGS += $(DEBUGFLAGS)
debug: $(EXEC)

clean:
	rm -f $(EXEC)
	rm -rf $(OBJ_DIR)

test: ${EXEC}
	python3 $(TEST_SCRIPT)
