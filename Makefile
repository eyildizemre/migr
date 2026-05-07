CC = gcc
CFLAGS = -Wall -Wextra -g

TARGET = migr
SRCS = main.c detect.c report.c backup.c packages.c restore.c utils.c fileops.c
OBJS = $(SRCS:.c=.o)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TARGET)
	cd tests && bash test.sh

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: clean test