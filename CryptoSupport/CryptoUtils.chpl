require "CryptoSupport/rsaKeySupport.chpl";

module CryptoUtils {

  use rsaKeySupport;
  use rsaKeySupport;

  class CryptoBuffer {
    var _len: int = 0;
    var buffDomain: domain(1);
    var buff: [buffDomain] uint(8);

    /* Initializes buffer to accomodate strings */
    proc CryptoBuffer(s: string) {
      this._len = s.length;
      this.buffDomain = {0..this._len-1};
      for i in this.buffDomain do {
        this.buff[i] = ascii(s[i + 1]);
      }
    }

    /* Initializes buffer to accomodate uint(8) arrays */
    proc CryptoBuffer(s: [] uint(8)) {
      this._len = s.size;
      this.buffDomain = {0..this._len-1};
      for i in this.buffDomain do {
        this.buff[i] = s[i];
      }
    }

    /* Returns the internal array within the buffer */
    proc getBuffData() {
      return this.buff;
    }

    /* Returns the pointer to the internal array within the buffer */
    proc getBuffPtr() {
      return c_ptrTo(this.buff);
    }

    /*Returns the size/length if the internal array within the buffer */
    proc getBuffSize() {
      return this._len;
    }

    /* Returns hexadecimal array representation of the buffer */
    proc toHex() {
      var buffHex: [this.buffDomain] string;
      for i in this.buffDomain do {
        buffHex[i] = "%xu".format(this.buff[i]);
      }
      return buffHex;
    }

    /* Returns hexadecimal string representation of the buffer */
    proc toHexString() {
      var buffHexString: string;
      for i in this.buffDomain do {
        buffHexString += "%xu".format(this.buff[i]);
      }
      return buffHexString;
    }
  }

  class RSAKey {
    var keyLen: int;
    var keyObj: asymmetricPrimitives.EVP_PKEY_PTR;

    proc RSAKey(keyLen: int) {
      if (keyLen != 1024 && keyLen != 2048 && keyLen != 4096) {
        halt("RSAKey: Invalid key length.");
      }
      this.keyLen = keyLen;
      this.keyObj = rsaKeySupport.generateKeys(this.keyLen);
    }

    proc getKeyPair() {
      return this.keyObj;
    }
    /* TODO: Key access functions to be added */
  }

  class Envelope {
    var keyDomain: domain(1);
    var keys: [keyDomain] CryptoBuffer;
    var iv: CryptoBuffer;
    var value: CryptoBuffer;

    proc Envelope(iv: CryptoBuffer, encSymmKey: [] CryptoBuffer, encSymmValue: CryptoBuffer) {
      this.keyDomain = {0..(encSymmKey.size-1)};
      for i in this.keyDomain do {
        this.keys[i] = encSymmKey[i];
      }
      this.iv = iv;
      this.value = encSymmValue;
    }

    proc getEncMessage() {
      return this.value;
    }

    proc getIV() {
      return this.iv;
    }

    proc getEncKeyByIndex(i: int) {
      return this.keys[i];
    }

    proc getEncKeys() {
      return this.keys;
    }
 }
}
