nf-queue-redirect: main.c
	gcc main.c -Wall `pkg-config --cflags --libs libnfnetlink libnetfilter_queue` -o nf-queue-redirect
clean:
	rm -f nf-queue-redirect

