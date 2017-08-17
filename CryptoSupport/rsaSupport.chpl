require "CryptoSupport/handlers/rsa_complex_bypass_handler.h";
require "openssl/pem.h", "openssl/bn.h", "openssl/bio.h";
require "openssl/evp.h";
require "CryptoSupport/CryptoUtils.chpl";
require "CryptoSupport/primitives/asymmetricPrimitives.chpl";

module rsaSupport {
  use CryptoUtils;
  use CryptoUtils;
  use asymmetricPrimitives;
  use asymmetricPrimitives;

  proc rsaEncrypt(keys, plaintext, ref iv: [] uint(8), ref encSymmKeys: [] CryptoBuffer) {

    var ctx: asymmetricPrimitives.EVP_CIPHER_CTX;
    asymmetricPrimitives.EVP_CIPHER_CTX_init(ctx);

    var numKeys = keys.size;
    for i in {0..(numKeys-1)} do {
      var keySize = asymmetricPrimitives.EVP_PKEY_size(keys[i+1].getKeyPair());
      var dummyMalloc: [0..(keySize: int(64))] uint(8);
      encSymmKeys[i] = new CryptoBuffer(dummyMalloc);
    }

    var encSymmKeysPtr: [0..(numKeys-1)] c_ptr(uint(8));
    var encryptedSymKeyLen: c_int = 0;
    for i in {0..(numKeys - 1)} do {
      encSymmKeysPtr[i] = c_ptrTo(encSymmKeys[i].getBuffData());
    }

    var keyObjs: [0..(numKeys-1)] asymmetricPrimitives.EVP_PKEY_PTR;
    for i in {0..(numKeys - 1)} do {
      keyObjs[i] = keys[i+1].getKeyPair();
    }

    var plaintextBuff = plaintext.getBuffData();
    var plaintextBuffLen = plaintext.getBuffSize();
    var ciphertextLen = plaintextBuffLen + 16;
    var cipherDomain: domain(1) = {0..(ciphertextLen - 1)};
    var updatedCipherLen: c_int = 0;
    var ciphertext: [cipherDomain] uint(8);

    asymmetricPrimitives.EVP_SealInit(ctx, asymmetricPrimitives.EVP_aes_256_cbc(),
                                      c_ptrTo(encSymmKeysPtr),
                                      c_ptrTo(encryptedSymKeyLen): c_ptr(c_int),
                                      c_ptrTo(iv): c_ptr(c_uchar),
                                      c_ptrTo(keyObjs), numKeys: c_int);
    asymmetricPrimitives.EVP_SealUpdate(ctx,
                                        c_ptrTo(ciphertext): c_ptr(c_uchar),
                                        c_ptrTo(ciphertextLen): c_ptr(c_int),
                                        c_ptrTo(plaintextBuff): c_ptr(c_uchar),
                                        plaintextBuffLen: c_int);
    asymmetricPrimitives.EVP_SealFinal(ctx,
                                       c_ptrTo(ciphertext): c_ptr(c_uchar),
                                       c_ptrTo(updatedCipherLen): c_ptr(c_int));

    cipherDomain = {0..((ciphertextLen + updatedCipherLen) - 1)};
    return ciphertext;
  }
}
