require "openssl/evp.h", "-lcrypto";
require "openssl/aes.h", "openssl/rand.h";

require "CryptoSupport/hashSupport.chpl";
require "CryptoSupport/CryptoUtils.chpl";

module Crypto {

  use hashSupport;
  use hashSupport;
  use CryptoUtils;
  use CryptoUtils;


  class Hash {
    var hashLen: int;
    var digestName: string;
    var hashDomain: domain(1);
    var hashSpace: [hashDomain] uint(8);

    /* Hash digest constructor that initializes the algorithm */
    proc Hash(digestName: string) {
      select digestName {
        when "MD5"        do this.hashLen = 16;
        when "SHA1"       do this.hashLen = 20;
        when "SHA224"     do this.hashLen = 28;
        when "SHA256"     do this.hashLen = 32;
        when "SHA384"     do this.hashLen = 48;
        when "SHA512"     do this.hashLen = 64;
        when "RIPEMD160"  do this.hashLen = 20;
        otherwise do halt("A digest with the name \'" + digestName + "\' doesn't exist.");
      }
      this.digestName = digestName;
      this.hashDomain = {0..this.hashLen-1};
    }

    /* Returns the name of the digest algorithm in use */
    proc getDigestName() {
      return this.digestName;
    }

    /* Returns the buffer of the hash */
    proc getDigest(inputBuffer: CryptoBuffer) {
      this.hashSpace = hashSupport.digestPrimitives(this.digestName, this.hashLen, inputBuffer);
      var hashBuffer = new CryptoBuffer(this.hashSpace);
      return hashBuffer;
    }
  }

}
