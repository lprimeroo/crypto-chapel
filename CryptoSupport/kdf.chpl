require "openssl/evp.h";
require "Crypto.chpl";
require "CryptoSupport/CryptoUtils.chpl";

module KDF {

  use CryptoUtils;
  use CryptoUtils;
  use Crypto;
  use Crypto;

  extern type EVP_MD;
  extern type EVP_MD_PTR = c_ptr(EVP_MD);
  extern proc OpenSSL_add_all_digests();
  extern proc EVP_get_digestbyname(name: c_string): EVP_MD_PTR;
  extern proc PKCS5_PBKDF2_HMAC(pass: c_string,
                                passlen: c_int,
                                const salt: c_ptr(c_uchar),
                                saltlen: c_int,
                                iterCount: c_int,
                                const digest: EVP_MD_PTR,
                                keylen: c_int,
                                outx: c_ptr(c_uchar)): c_int;

  /* Routine for PBKDF2 mechanism */                              
  proc PBKDF2_HMAC(userKey: string, saltBuff: CryptoBuffer, bitLen: int, iterCount: int, digest: Hash) {

    /* Loads all digests into the table*/
    OpenSSL_add_all_digests();

    var key: [0..(bitLen-1)] uint(8);
    var salt = saltBuff.getBuffData();
    var userKeyLen = userKey.length;
    var digestName = digest.getDigestName();

    /* Use the specified digest */
    const md = EVP_get_digestbyname(digestName.c_str());

    PKCS5_PBKDF2_HMAC(userKey.c_str(),
                      userKeyLen: c_int,
                      c_ptrTo(salt): c_ptr(c_uchar),
                      bitLen: c_int,
                      iterCount: c_int,
                      md,
                      bitLen: c_int,
                      c_ptrTo(key): c_ptr(c_uchar));

    var keyBuff = new CryptoBuffer(key);
    return keyBuff;
  }

}
