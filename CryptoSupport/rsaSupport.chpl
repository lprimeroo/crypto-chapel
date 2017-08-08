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

  proc rsaInit(bits: int) {

    var localKeyPair: EVP_PKEY_PTR;

    var keyCtx = asymmetricPrimitives.EVP_PKEY_CTX_new_id(6: c_int,
                                                          c_nil: asymmetricPrimitives.ENGINE_PTR);

    asymmetricPrimitives.EVP_PKEY_keygen_init(keyCtx);
    asymmetricPrimitives.EVP_PKEY_CTX_set_rsa_keygen_bits(keyCtx, bits: c_int);
    asymmetricPrimitives.EVP_PKEY_keygen(keyCtx, localKeyPair);
    return localKeyPair;
  }


  proc rsaEncrypt(keyPair: EVP_PKEY_PTR, plaintext: CryptoBuffer, ref iv: [] uint(8),
                  ref encSymmKey: [] uint(8), ref ciphertext: [] uint(8), ref cipherDomain: domain(1)) {

    var ctx: asymmetricPrimitives.EVP_CIPHER_CTX;
    asymmetricPrimitives.EVP_CIPHER_CTX_init(ctx);

    var plaintextBuff = plaintext.getBuffData();
    var plaintextBuffLen = plaintext.getBuffSize();

    var ciphertextLen = plaintextBuffLen + 16;
    var updatedCipherLen: c_int = 0;

    var encryptedSymKeyLen: c_int = 0;
    var encryptedSymKeyPtr = c_ptrTo(encSymmKey);
    var keyPairCopy = keyPair;
    asymmetricPrimitives.EVP_SealInit(ctx, asymmetricPrimitives.EVP_aes_256_cbc(), encryptedSymKeyPtr,
                                      c_ptrTo(encryptedSymKeyLen): c_ptr(c_int),
                                      c_ptrTo(iv): c_ptr(c_uchar), keyPairCopy, 1: c_int);
    asymmetricPrimitives.EVP_SealUpdate(ctx,
                                        c_ptrTo(ciphertext): c_ptr(c_uchar),
                                        c_ptrTo(ciphertextLen): c_ptr(c_int),
                                        c_ptrTo(plaintextBuff): c_ptr(c_uchar),
                                        plaintextBuffLen: c_int);
    asymmetricPrimitives.EVP_SealFinal(ctx,
                                       c_ptrTo(ciphertext): c_ptr(c_uchar),
                                       c_ptrTo(updatedCipherLen): c_ptr(c_int));
    cipherDomain = {0..((ciphertextLen + updatedCipherLen) - 1)};
  }


  proc rsaDecrypt(keyPair: EVP_PKEY_PTR, iv: CryptoBuffer, encKey: CryptoBuffer, ciphertext: CryptoBuffer) {

    var ctx: asymmetricPrimitives.EVP_CIPHER_CTX;
    asymmetricPrimitives.EVP_CIPHER_CTX_init(ctx);

    var encryptedSymKey = encKey.getBuffData();
    var encryptedSymKeyLen = encKey.getBuffSize();
    var ciphertextBuff = ciphertext.getBuffData();
    var ciphertextBuffLen = ciphertext.getBuffSize();
    var ivBuff = iv.getBuffData();

    var plaintextLen = ciphertextBuffLen;
    var updatedPlainLen: c_int = 0;
    var plaintextDomain: domain(1) = {0..(plaintextLen)};
    var plaintext: [plaintextDomain] uint(8);

    asymmetricPrimitives.EVP_OpenInit(ctx,
                                      asymmetricPrimitives.EVP_aes_256_cbc(),
                                      c_ptrTo(encryptedSymKey): c_ptr(c_uchar),
                                      encryptedSymKeyLen: c_int,
                                      c_ptrTo(ivBuff): c_ptr(c_uchar),
                                      keyPair);

    asymmetricPrimitives.EVP_OpenUpdate(ctx,
                                        c_ptrTo(plaintext): c_ptr(c_uchar),
                                        c_ptrTo(plaintextLen): c_ptr(c_int),
                                        c_ptrTo(ciphertextBuff): c_ptr(c_uchar),
                                        ciphertextBuffLen: c_int);
    asymmetricPrimitives.EVP_OpenFinal(ctx,
                                       c_ptrTo(plaintext): c_ptr(c_uchar),
                                       c_ptrTo(updatedPlainLen): c_ptr(c_int));

   plaintextDomain = {0..((plaintextLen + updatedPlainLen) - 1)};

   return plaintext;
  }
}
