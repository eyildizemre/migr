CC = gcc
CFLAGS = -Wall -Wextra -g

TARGET = migr
SRCS = main.c detect.c report.c backup.c packages.c restore.c utils.c
OBJS = $(SRCS:.c=.o)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: clean