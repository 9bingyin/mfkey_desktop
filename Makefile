CC = gcc
CFLAGS = -O3 -Wall -Wextra -std=c99 -funroll-all-loops
TARGET = mfkey_desktop
SOURCES = mfkey_desktop.c

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

.PHONY: all clean install
