all: aes output.txt

aes: aes-128.c aes-128.h main.c
	@rm -f *.o aes output.txt
	@gcc -o aes main.c aes-128.c aes-128.h

output.txt: 
	@./aes

clean:
	@rm -f *.o aes output.txt
