# ZenithLock Makefile

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -Iinclude -lcrypto

# Directories
SRC_DIR = src
OBJ_DIR = obj

# Final target name (we call our tool "zenithlock")
TARGET = zenithlock

# Installation directories (can be overridden on the command line)
PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/share/man/man1

# Source and Object Files
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

# Phony targets
.PHONY: all clean install uninstall

# Default target: build ZenithLock
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Clean build files
clean:
	rm -rf $(OBJ_DIR) $(TARGET)

# Install target: installs the executable and the man page
install: $(TARGET)
	@echo "Installing $(TARGET) to $(BINDIR) and man page to $(MANDIR)..."
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	install -d $(DESTDIR)$(MANDIR)
	install -m 644 encryptor.1 $(DESTDIR)$(MANDIR)/$(TARGET).1

# Uninstall target: removes the installed files
uninstall:
	@echo "Uninstalling $(TARGET) from $(BINDIR) and man page from $(MANDIR)..."
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)$(MANDIR)/$(TARGET).1

# at the bottom of your Makefile

TEST_OBJS = obj/blowfish.o obj/algorithm.o

tests/blowfish_test: tests/blowfish_test.c $(TEST_OBJS)
	$(CC) $(CFLAGS) -Iinclude -o $@ $^ -lcrypto

