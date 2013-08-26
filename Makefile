all:
	dmd -g telehash.d libevent.d json.d cryptopp.d cryptopp-d.o -Iopenssl -L-levent -L-L/usr/local/lib -L-lcryptopp -L-lstdc++

crypto:
	clang -g -m64 -c cryptopp-d.cpp -I/usr/local/include
	dmd -g test-crypto.d cryptopp-d.o -L-lcryptopp -L-lstdc++ -L-L/usr/local/lib
	
