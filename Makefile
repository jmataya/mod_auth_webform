CC=apxs2
CFLAGS=-c
IFLAGS=-i

all:
	$(CC) $(CFLAGS) mod_auth_webform.c

install:
	$(CC) $(IFLAGS) mod_auth_webform.la

clean:
	rm *.la *.lo *.slo
