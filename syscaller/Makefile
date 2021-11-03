CXX = gcc
SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)

CPPFLAGS = -Wall -Werror
LDFLAGS =

syscaller: $(OBJ)
	$(CC) $(CPPFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(OBJ) app
