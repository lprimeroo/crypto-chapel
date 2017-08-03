module asymmetricPrimitives {
  extern type RSA;
  extern type BIGNUM;
  extern type BIO;
  extern type BN_ULONG;
  extern type BN_GENCB;
  extern type BIO_METHOD;
  extern type EVP_CIPHER;
  extern type pem_password_cb;

  extern var RSA_F4: BN_ULONG;

  extern type RSA_PTR = c_ptr(RSA);
  extern type BIGNUM_PTR = c_ptr(BIGNUM);
  extern type BIO_PTR = c_ptr(BIO);
  extern type BN_GENCB_PTR = c_ptr(BN_GENCB);
  extern type BIO_METHOD_PTR = c_ptr(BIO_METHOD);
  extern type EVP_CIPHER_PTR = c_ptr(EVP_CIPHER);
  extern type PEM_PWD_CB_PTR = c_ptr(pem_password_cb);

  extern proc BN_new(): BIGNUM_PTR;
  extern proc BN_set_word(a: BIGNUM_PTR, w: BN_ULONG): c_int;
  extern proc BIO_new(types: BIO_METHOD_PTR): BIO_PTR;
  extern proc BIO_s_mem(): BIO_METHOD_PTR;
  extern proc BIO_pending(b: BIO_PTR): c_int;
  extern proc BIO_read(b: BIO_PTR, buf: c_void_ptr, len: c_int): c_int;
  extern proc BIO_new_file(filename: c_string, mode: c_string): BIO_PTR;


  extern proc RSA_new(): RSA_PTR;
  extern proc RSA_size(const rsa: RSA_PTR): c_int;
  extern proc RSA_generate_key_ex(rsa: RSA_PTR, bits: c_int, e: BIGNUM_PTR, cb: BN_GENCB_PTR): c_int;

  extern proc PEM_write_bio_RSAPrivateKey(bp: BIO_PTR,
                                          x: RSA_PTR,
                                          const enc: EVP_CIPHER_PTR,
                                          kstr: c_ptr(c_uchar),
                                          klen: c_int,
                                          cb: PEM_PWD_CB_PTR,
                                          u: c_void_ptr): c_int;
  extern proc PEM_write_bio_RSAPublicKey(bp: BIO_PTR, x: RSA_PTR): c_int;
}
