CXX= /usr/bin/g++
CXXFLAGS= --std=c++11 -g -Wno-deprecated-declarations -Wno-write-strings
LCRYPTO++ := -lcryptopp
ICRYPTO++ := -I /usr/include/crypto++
LBCRYPT := -lbcrypt
LPROTO := $(shell pkg-config --libs protobuf)

all:	client server

client: client.cpp clientTools.o;
	${CXX} ${CXXFLAGS} ${ICRYPTO++} client.cpp clientTools.o -o client ${LBCRYPT} ${LCRYPTO++} ${LPROTO}

server: server.cpp database.o;
	${CXX} ${CXXFLAGS} ${ICRYPTO++} server.cpp database.o -o server -lsqlite3 ${LBCRYPT} ${LCRYPTO++} ${LPROTO}
	
database.o: database.cpp database.h
	${CXX} ${CXXFLAGS} ${ICRYPTO++} -c database.cpp -lsqlite3 ${LCRYPTO++} ${LPROTO}
	
sample: Sample.cpp clientTools.o
	${CXX} ${CXXFLAGS} ${ICRYPTO++} Sample.cpp clientTools.o -o sample ${LCRYPTO++} ${LPROTO}
	
clientTools.o: clientTools.cpp clientTools.h
	${CXX} ${CXXFLAGS} ${ICRYPTO++} -c clientTools.cpp ${LCRYPTO++} ${LPROTO}
	

clean:
	rm client server *.o
