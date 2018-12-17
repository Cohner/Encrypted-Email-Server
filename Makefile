CXX= /usr/bin/g++
CXXFLAGS= --std=c++11 -g -Wno-deprecated-declarations -Wno-write-strings
LCRYPTO++ := -lcryptopp
ICRYPTO++ := -I /usr/include/crypto++
LBCRYPT := -lbcrypt
LPROTO := $(shell pkg-config --libs protobuf)

all:	client server

client: client.cpp clientTools.o packet.pb.h;
	${CXX} ${CXXFLAGS} ${ICRYPTO++} client.cpp clientTools.o -o client ${LBCRYPT} ${LCRYPTO++} ${LPROTO}

server: server.cpp database.o packet.pb.h;
	${CXX} ${CXXFLAGS} ${ICRYPTO++} server.cpp database.o -o server -lsqlite3 ${LBCRYPT} ${LCRYPTO++} ${LPROTO}
	
tests: test.cpp clientTools.o database.o packet.pb.h
	${CXX} ${CXXFLAGS} ${ICRYPTO++} test.cpp clientTools.o database.o -o test -lsqlite3 ${LBCRYPT} ${LCRYPTO++} ${LPROTO}
	mv ./test ./tests
	
database.o: database.cpp database.h packet.pb.h
	${CXX} ${CXXFLAGS} ${ICRYPTO++} -c database.cpp -lsqlite3 ${LCRYPTO++} ${LPROTO}
	
clientTools.o: clientTools.cpp clientTools.h
	${CXX} ${CXXFLAGS} ${ICRYPTO++} -c clientTools.cpp -lsqlite3 ${LBCRYPT} ${LCRYPTO++} ${LPROTO}
	

clean:
	rm client server sample *.o
