CC = gcc
CFLAGS = -O3 -Wall -Wextra -std=c99
TARGET = mfkey_desktop
SOURCES = mfkey_desktop.c pixel_ui.c

# Default target - direct build without .o files
all: $(TARGET)

# Direct build - no intermediate .o files
$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET)

# Clean generated files
clean:
	rm -f $(TARGET)

# Install to system
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

.PHONY: all clean install
