CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET = calculator
SRC = calculator.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) -lm

clean:
	rm -f $(TARGET)