require "openssl/evp.h";
require "CryptoSupport/CryptoUtils.chpl";
//require "CryptoSupport/KDF.chpl"

module aesSupport {

  use CryptoUtils;
  use CryptoUtils;

  extern type EVP_CIPHER;
  extern type EVP_CIPHER_CTX;
  extern type EVP_MD;
  extern type ENGINE;

  extern type EVP_CIPHER_PTR = c_ptr(EVP_CIPHER);
  extern type EVP_CIPHER_CTX_PTR = c_ptr(EVP_CIPHER_CTX);
  extern type EVP_MD_PTR = c_ptr(EVP_MD);
  extern type ENGINE_PTR = c_ptr(ENGINE);

  extern proc RAND_bytes(buf: c_ptr(c_uchar), num: c_int) : c_int;

  extern proc EVP_sha256(): EVP_MD_PTR;

  extern proc EVP_CIPHER_CTX_free(ref c: EVP_CIPHER_CTX);
  extern proc EVP_CIPHER_CTX_init(ref c: EVP_CIPHER_CTX): c_int;
  extern proc EVP_EncryptInit_ex(ref ctx: EVP_CIPHER_CTX,
                                const cipher: EVP_CIPHER_PTR,
                                impl: ENGINE_PTR,
                                const key: c_ptr(c_uchar),
                                const iv: c_ptr(c_uchar)): c_int;
  extern proc EVP_EncryptUpdate(ref ctx: EVP_CIPHER_CTX,
                                outm: c_ptr(c_uchar),
                                outl: c_ptr(c_int),
                                const ins: c_ptr(c_uchar),
                                inl: c_int): c_int;
  extern proc EVP_EncryptFinal_ex(ref ctx: EVP_CIPHER_CTX,
                                  outm: c_ptr(c_uchar),
                                  outl: c_ptr(c_int)): c_int;
  extern proc EVP_DecryptInit_ex(ref ctx: EVP_CIPHER_CTX,
                                const cipher: EVP_CIPHER_PTR,
                                impl: ENGINE_PTR,
                                const key: c_ptr(c_uchar),
                                const iv: c_ptr(c_uchar)): c_int;
  extern proc EVP_DecryptUpdate(ref ctx: EVP_CIPHER_CTX,
                                outm: c_ptr(c_uchar),
                                outl: c_ptr(c_int),
                                const ins: c_ptr(c_uchar),
                                inl: c_int): c_int;
  extern proc EVP_DecryptFinal_ex(ref ctx: EVP_CIPHER_CTX,
                                  outm: c_ptr(c_uchar),
                                  outl: c_ptr(c_int)): c_int;

  extern proc EVP_aes_128_cbc(): EVP_CIPHER_PTR;
  extern proc EVP_aes_128_ecb(): EVP_CIPHER_PTR;
  extern proc EVP_aes_128_cfb(): EVP_CIPHER_PTR;
  extern proc EVP_aes_128_ofb(): EVP_CIPHER_PTR;
  extern proc EVP_aes_192_cbc(): EVP_CIPHER_PTR;
  extern proc EVP_aes_192_ecb(): EVP_CIPHER_PTR;
  extern proc EVP_aes_192_cfb(): EVP_CIPHER_PTR;
  extern proc EVP_aes_192_ofb(): EVP_CIPHER_PTR;
  extern proc EVP_aes_256_cbc(): EVP_CIPHER_PTR;
  extern proc EVP_aes_256_ecb(): EVP_CIPHER_PTR;
  extern proc EVP_aes_256_cfb(): EVP_CIPHER_PTR;
  extern proc EVP_aes_256_ofb(): EVP_CIPHER_PTR;

  extern proc PKCS5_PBKDF2_HMAC(pass: c_string,
                                passlen: c_int,
                                const salt: c_ptr(c_uchar),
                                saltlen: c_int,
                                iterCount: c_int,
                                const digest: EVP_MD_PTR,
                                keylen: c_int,
                                outx: c_ptr(c_uchar)): c_int;

  proc getPBKDFKey(userKey: string, bitLen: int, saltBuff: CryptoBuffer) {
    var key: [0..(bitLen-1)] uint(8);
    var salt = saltBuff.getBuffData();
    var userKeyLen = userKey.length;
    var iterCount = 1000;
    const md = EVP_sha256();

    PKCS5_PBKDF2_HMAC(userKey.c_str(),
                      userKeyLen: c_int,
                      c_ptrTo(salt): c_ptr(c_uchar),
                      bitLen: c_int,
                      iterCount: c_int,
                      md,
                      bitLen: c_int,
                      c_ptrTo(key): c_ptr(c_uchar));
    return key;
  }

  proc getIV(bitLen: int) {
    var iv: [0..(bitLen-1)] uint(8);
    RAND_bytes(c_ptrTo(iv): c_ptr(c_uchar), bitLen: c_int);
    return iv;
  }

  proc aesEncrypt(plaintext: CryptoBuffer, key: CryptoBuffer, IV: CryptoBuffer, cipher: EVP_CIPHER_PTR) {

    /* Initialize the context */
    var ctx: EVP_CIPHER_CTX;
    EVP_CIPHER_CTX_init(ctx);

    /* Get buffer contents */
    var keyData = key.getBuffData();
    var ivData = IV.getBuffData();
    var plaintextData = plaintext.getBuffData();
    var plaintextLen = plaintext.getBuffSize();

    /* Allocating space for obtaining the ciphertext */
    var ciphertextLen = plaintextLen + 16; // 16 is the MAX_BLOCK_SIZE for AES
    var cipherDomain: domain(1) = {0..ciphertextLen};
    var updatedCipherLen: c_int = 0;
    var ciphertext: [cipherDomain] uint(8);

    EVP_EncryptInit_ex(ctx,
                       cipher,
                       c_nil: ENGINE_PTR,
                       c_ptrTo(keyData): c_ptr(c_uchar),
                       c_ptrTo(ivData): c_ptr(c_uchar));
    EVP_EncryptUpdate(ctx,
                      c_ptrTo(ciphertext): c_ptr(c_uchar),
                      c_ptrTo(ciphertextLen): c_ptr(c_int),
                      c_ptrTo(plaintextData): c_ptr(c_uchar),
                      plaintextLen: c_int);
    EVP_EncryptFinal_ex(ctx,
                        c_ptrTo(ciphertext): c_ptr(c_uchar),
                        c_ptrTo(updatedCipherLen): c_ptr(c_int));

    cipherDomain = {0..((ciphertextLen + updatedCipherLen) - 1)};
    return ciphertext;
  }

  proc aesDecrypt(ciphertext: CryptoBuffer, key: CryptoBuffer, IV: CryptoBuffer, cipher: EVP_CIPHER_PTR) {

    /* Initialize the context */
    var ctx: EVP_CIPHER_CTX;
    EVP_CIPHER_CTX_init(ctx);

    /* Get buffer contents */
    var keyData = key.getBuffData();
    var ivData = IV.getBuffData();
    var ciphertextData = ciphertext.getBuffData();
    var ciphertextLen = ciphertext.getBuffSize();

    /* Allocating space for obtaining the plaintext */
    var plaintextLen = ciphertextLen;
    var updatedPlainLen: c_int = 0;
    var plainDomain: domain(1) = {0..plaintextLen};
    var plaintext: [plainDomain] uint(8);

    EVP_DecryptInit_ex(ctx,
                       cipher,
                       c_nil: ENGINE_PTR,
                       c_ptrTo(keyData): c_ptr(c_uchar),
                       c_ptrTo(ivData): c_ptr(c_uchar));
    EVP_DecryptUpdate(ctx,
                      c_ptrTo(plaintext): c_ptr(c_uchar),
                      c_ptrTo(plaintextLen): c_ptr(c_int),
                      c_ptrTo(ciphertextData): c_ptr(c_uchar),
                      ciphertextLen: c_int);
    EVP_DecryptFinal_ex(ctx,
                        c_ptrTo(plaintext): c_ptr(c_uchar),
                        c_ptrTo(updatedPlainLen): c_ptr(c_int));

   plainDomain = {0..((plaintextLen + updatedPlainLen) - 1)};
   return plaintext;
  }

}
