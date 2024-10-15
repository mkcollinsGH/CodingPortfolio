CC = g++
CFLAGS = -std=c++20

SRCDIR = src
EXECDIR = exec
TESTDIR = test 

encprog = shiftenc_cpp
decprog = shiftdec_cpp

encsrc = ShiftEncipher.cpp
decsrc = ShiftDecipher.cpp

.PHONY: default clean cleantest
default: shiftenc_cpp shiftdec_cpp
	
shiftenc_cpp :  
	$(CC) $(CFLAGS) -o $(EXECDIR)/$(encprog) $(SRCDIR)/$(encsrc)
	
shiftdec_cpp :  
	$(CC) $(CFLAGS) -o $(EXECDIR)/$(decprog) $(SRCDIR)/$(decsrc)

clean:
	rm -f $(EXECDIR)/$(encprog)
	rm -f $(EXECDIR)/$(decprog)

cleantest:
	rm -f $(TESTDIR)/tempresults/*
