CC=gcc
CFLAGS=-c -Wall -g
LDFLAGS=
EXTRAFLAGS ?=

# The file name changes but will default to 'DEFAULT' if not provided
FILENAME ?= DEFAULT

# The source file is based on FILENAME, and OBJECTS holds the corresponding .o file
SOURCES = $(FILENAME).c
OBJECTS = $(FILENAME).o

# The fixed file that always stays the same
FIXED_OBJECT = otherFunctions.o packetFunctions.o ethernet.o ip.o tcp.o udp.o dns.o

# The final executable name is based on the FILENAME
EXECUTABLE = $(FILENAME)

# The default target, which builds the executable
all: $(EXECUTABLE)

# Debug mode with extra flags
debug: CFLAGS += -DDEBUG -g
debug: $(EXECUTABLE)

# Debug mode without optimizations
debugNoOpt: CFLAGS += -DDEBUG -g -O0
debugNoOpt: $(EXECUTABLE)

# Address sanitizer
ASAN: CFLAGS+= -DDEBUG -g -fsanitize=address -O0
ASAN: LDFLAGS+= -fsanitize=address
ASAN:$(EXECUTABLE)

# The rule to link the objects into the final executable
$(EXECUTABLE): $(OBJECTS) $(FIXED_OBJECT)
	$(CC) $(LDFLAGS) $(OBJECTS) $(FIXED_OBJECT) -o $@ $(EXTRAFLAGS)

# Clean up object files and executables
clean:
	rm -f $(OBJECTS) $(EXECUTABLE)
