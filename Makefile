.PHONY: all

CC=gcc
LIBS=-lkrb5 -lprot -lauth -lsys -lrxkad -lrx -lafsutil -lutil -llwp -lubik -lcom_err -ldes -lrxstat -ldb
LIBDIRS=-L/usr/lib/afs -L/usr/lib64/afs
CFLAGS=-g

all: get_afs_tokens libafstokens.a

clean:
	rm -f afstokens *.o *.out *.a

test: get_afs_tokens
	./get_afs_tokens

OBJS=afs.o krb5.o db.o afstokens.o logging.o

libafstokens.a: $(OBJS)
	$(AR) rcs libafstokens.a $(OBJS)

get_afs_tokens: libafstokens.a get_afs_tokens.o
	$(CC) $(CFLAGS) get_afs_tokens.c -o $@ -lafstokens -L. $(LIBS) $(LIBDIRS)
