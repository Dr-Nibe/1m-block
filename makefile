TARGET = 1m-block
CC = gcc
CFLAGS = -lnetfilter_queue

all: $(TARGET)

$(TARGET): 1m-block.c
		$(CC) -o $(TARGET) 1m-block.c $(CFLAGS)

clean:
		rm -f $(TARGET)