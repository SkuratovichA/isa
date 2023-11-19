# Author: Aliaksandr Skuratovich (xskura01)

CC = g++
CXXFLAGS = -std=c++20 -Wall
DEBUGFLAGS = -DDEBUG -g
LDFLAGS =
EXEC = dns
SRC_DIR = src
OBJ_DIR = object_files
SOURCES = $(SRC_DIR)/main.cpp
HEADERS = $(SRC_DIR)/argparser.h $(SRC_DIR)/dns.h $(SRC_DIR)/udp.h $(SRC_DIR)/utils.h
OBJECTS = $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(SOURCES))
TEST_SCRIPT = test_dns.py
TEST_VENV = test_venv

.PHONY: all clean test debug archive

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
	rm -rf $(TEST_VENV)
	rm -rf $(OBJ_DIR)

test: all
	rm -rf $(TEST_VENV)
	python3 -m venv $(TEST_VENV)
	$(TEST_VENV)/bin/pip install -r requirements.txt
	$(TEST_VENV)/bin/python $(TEST_SCRIPT)

archive:
	tar -cvf xskura01.tar $(SRC_DIR) Makefile requirements.txt README.md $(TEST_SCRIPT) manual.pdf
