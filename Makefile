CC = gcc
CFLAGS = -Wall -Wextra -g -I src

TARGET = migr
VPATH = src
SRCS = main.c detect.c report.c backup.c packages.c restore.c utils.c fileops.c xdg.c manifest.c
OBJS = $(SRCS:.c=.o)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

TEST_DETECT = tests/test_detect
TEST_PATHJOIN = tests/test_pathjoin

$(TEST_DETECT): tests/test_detect.c detect.o
	$(CC) $(CFLAGS) -o $@ tests/test_detect.c detect.o

$(TEST_PATHJOIN): tests/test_pathjoin.c utils.o
	$(CC) $(CFLAGS) -o $@ tests/test_pathjoin.c utils.o

test: $(TARGET) $(TEST_DETECT) $(TEST_PATHJOIN)
	./$(TEST_DETECT)
	./$(TEST_PATHJOIN)
	cd tests && bash test.sh

clean:
	rm -f $(OBJS) $(TARGET) $(TEST_DETECT) $(TEST_PATHJOIN)

.PHONY: clean test