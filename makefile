all: binder librpc.a 

binder: binder.c
	g++ -o binder binder.c

librpc.a: rpc.cpp rpc.h
	g++ -c rpc.cpp -lpthread
	ar -cvq librpc.a rpc.o

clean:
	rm *.o librpc.a binder
