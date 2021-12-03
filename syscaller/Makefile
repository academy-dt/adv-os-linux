CXX = gcc

CPPFLAGS = -Wall -Werror
LDFLAGS =

test.out: test.o shared.o
	$(CC) $(CPPFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f *.out *.o
