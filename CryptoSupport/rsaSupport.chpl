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

  proc rsaEncrypt(keys: [] RSAKey, plaintext: CryptoBuffer, ref iv: [] uint(8), ref encSymmKeys: [] CryptoBuffer) {

    var ctx: asymmetricPrimitives.EVP_CIPHER_CTX;
    asymmetricPrimitives.EVP_CIPHER_CTX_init(ctx);

    var numKeys = keys.size;
    for i in {0..(numKeys-1)} do {
      var keySize = asymmetricPrimitives.EVP_PKEY_size(keys[i+1].getKeyPair());
      var dummyMalloc: [0..((keySize - 1): int(64))] uint(8);
      encSymmKeys[i] = new CryptoBuffer(dummyMalloc);
    }

    var encSymmKeysPtr: [0..(numKeys-1)] c_ptr(uint(8));
    var encryptedSymKeyLen: c_int = 0;
    for i in {0..(numKeys - 1)} do {
      encSymmKeysPtr[i] = encSymmKeys[i].getBuffPtr();
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

  proc rsaDecrypt(key: RSAKey, iv: [] uint(8), ciphertext: [] uint(8), encKeys: [] CryptoBuffer) {

    var ctx: asymmetricPrimitives.EVP_CIPHER_CTX;
    asymmetricPrimitives.EVP_CIPHER_CTX_init(ctx);

    var numEncKeys = encKeys.size;
    var openErrCode = 0;

    for i in {0..(numEncKeys-1)} do {
      openErrCode = asymmetricPrimitives.EVP_OpenInit(ctx,
                                                      asymmetricPrimitives.EVP_aes_256_cbc(),
                                                      encKeys[i].getBuffPtr(),
                                                      encKeys[i].getBuffSize(): c_int,
                                                      c_ptrTo(iv): c_ptr(c_uchar),
                                                      key.getKeyPair());
      if (openErrCode) {
        break;
      }
    }

    if (!openErrCode) {
      halt("The RSAKey is an invalid match");
    }

    var plaintextLen = ciphertext.size;
    var updatedPlainLen: c_int = 0;
    var plaintextDomain: domain(1) = {0..(plaintextLen)};
    var plaintext: [plaintextDomain] uint(8);

    asymmetricPrimitives.EVP_OpenUpdate(ctx,
                                        c_ptrTo(plaintext): c_ptr(c_uchar),
                                        c_ptrTo(plaintextLen): c_ptr(c_int),
                                        c_ptrTo(ciphertext): c_ptr(c_uchar),
                                        ciphertext.size: c_int);
    asymmetricPrimitives.EVP_OpenFinal(ctx,
                                       c_ptrTo(plaintext): c_ptr(c_uchar),
                                       c_ptrTo(updatedPlainLen): c_ptr(c_int));

    plaintextDomain = {0..((plaintextLen + updatedPlainLen) - 1)};
    return plaintext;
  }
}
