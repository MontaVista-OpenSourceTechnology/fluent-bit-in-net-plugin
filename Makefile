
CC = cc

INCLUDES = -I/usr/local/include/fluent-bit -I/usr/local/include/fluent-bit/monkey

DEFINES = -fPIC

OBJS = net.o net_config.o net_conn.o

%.o: %.c
	$(CC) $(INCLUDES) $(DEFINES) -D__FILENAME__="\"$(PWD)/$<\"" -c $<

flb-in_net.so: $(OBJS)
	$(CC) -shared -o $@ $^

net.o: net.c net.h net_conn.h net_config.h

net_config.o: net_config.c net.h net_conn.h net_config.h

net_conn.o: net_conn.c net_conn.h

clean:
	rm -f flb-in_net.so $(OBJS)
