# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Werror -std=c11 -g

# Source files
SRC = twig.c utilities.c
OBJ = $(SRC:.c=.o)

# Output executable
TARGET = twig

# Default target
all: $(TARGET)

# Link object files to create the executable
$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET)
	mv $(TARGET) ../$(TARGET)

# Compile .c files into .o files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up compiled files
clean:
	rm -f $(OBJ) ../$(TARGET)

# Rebuild everything
rebuild: clean all

# Phony targets to prevent conflicts with file names
.PHONY: all clean rebuild