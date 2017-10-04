# NOTE:
# VIM USERS:
# :set noexpandtab - Use tabs, not spaces

OBJDIR          = obj
BINDIR          = bin
CC              = gcc
LDLIBS          = -lcrypto
#CFLAGS = -ggdb3 -Wall -Wextra -Werror -O0
CFLAGS          = -Wall
LINK_TARGET     = $(BINDIR)/openssl_evp_demo
SOURCES         = openssl_evp_demo.c
OBJS            = $(OBJDIR)/$(SOURCES:.c=.o)
REBUILDABLES    = $(OBJS) $(LINK_TARGET) encrypted_file decrypted_file

# Debug build
debug: CFLAGS += -DDEBUG -ggdb3 -O0
debug: $(LINK_TARGET)

# Release build
all : $(LINK_TARGET)

$(LINK_TARGET) : $(OBJS)
	$(CC) -o $@ $^ $(LDLIBS)

$(OBJS) : $(SOURCES)
	$(CC) $(CFLAGS) -c $^ -o $@

.PHONY: clean
clean:
	rm -f $(REBUILDABLES)
