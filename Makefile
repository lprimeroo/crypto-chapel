CHPL = chpl
CC = gcc
CFLAGS = -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include -lcrypto -lssl
SUPPORT = CryptoSupport


Crypto: Crypto.chpl
	$(CHPL) $(CFLAGS) -o Crypto Crypto.chpl CryptoSupport/hashSupport.chpl CryptoSupport/CryptoUtils.chpl --main-module=Crypto

CryptoUtils: $(SUPPORT)/CryptoUtils.chpl
	$(CHPL) $(CFLAGS) -o $(SUPPORT)/CryptoUtils $(SUPPORT)/CryptoUtils.chpl

hash: $(SUPPORT)/hashSupport.chpl
	$(CHPL) $(CFLAGS) -o $(SUPPORT)/hashSupport $(SUPPORT)/hashSupport.chpl
