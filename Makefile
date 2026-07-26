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
TEST_SPECIAL_FILES = tests/test_special_files

$(TEST_DETECT): tests/test_detect.c detect.o
	$(CC) $(CFLAGS) -o $@ tests/test_detect.c detect.o

$(TEST_PATHJOIN): tests/test_pathjoin.c utils.o
	$(CC) $(CFLAGS) -o $@ tests/test_pathjoin.c utils.o

$(TEST_SPECIAL_FILES): tests/test_special_files.c fileops.o utils.o
	$(CC) $(CFLAGS) -o $@ tests/test_special_files.c fileops.o utils.o

test: $(TARGET) $(TEST_DETECT) $(TEST_PATHJOIN) $(TEST_SPECIAL_FILES)
	./$(TEST_DETECT)
	./$(TEST_PATHJOIN)
	./$(TEST_SPECIAL_FILES)
	cd tests && bash test.sh

clean:
	rm -f $(OBJS) $(TARGET) $(TEST_DETECT) $(TEST_PATHJOIN) $(TEST_SPECIAL_FILES)

.PHONY: clean test
