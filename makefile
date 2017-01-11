CC=gcc
EXEC=genpcap
EXEC2=genpacket
LINKER_FLAGS= -o $(EXEC) -g -lm
LINKER_FLAGS2= -o $(EXEC2) -g -lm

CXXFLAGS +=  -Wall -g -DDBG=1 -pthread -O3

all: dmadrivercli dmadrivercli2

CLI_SRC= pcap.c genpcap.c #List of all .c
CLI2_SRC= genpacket.c #List of all .c


CLI_INC = pcap.h #List of all .h
CLI2_INC = pcap.h #List of all .h
CLI_OBJ = $(CLI_SRC:.c=.o)
CLI2_OBJ = $(CLI2_SRC:.c=.o)

dmadrivercli : $(CLI_OBJ) makefile
	$(CC) $(CXXFLAGS) $(CLI_OBJ) $(LINKER_FLAGS)


dmadrivercli2 : $(CLI2_OBJ) makefile
	$(CC) $(CXXFLAGS) $(CLI2_OBJ) $(LINKER_FLAGS2)


$(CLI2_OBJ) : %.o : %.c $(CLI2_INC) 
	$(CC) -c $(CXXFLAGS) $< -o $@

$(CLI_OBJ) : %.o : %.c $(CLI_INC) 
	$(CC) -c $(CXXFLAGS) $< -o $@

clean::
	rm -f $(EXEC) $(EXEC2)
	rm -f *.o

distclean realclean:: clean
	rm -f tags
	rm -f *~
	touch *



