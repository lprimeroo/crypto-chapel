require "openssl/evp.h";
require "CryptoSupport/CryptoUtils.chpl";

module hashSupport {

  use CryptoUtils;
  use CryptoUtils;

  /* Extern calls for OpenSSL hash primitives */
  extern type EVP_MD;
  extern type EVP_MD_CTX;
  extern type ENGINE;

  extern type EVP_MD_PTR = c_ptr(EVP_MD);
  extern type EVP_MD_CTX_PTR = c_ptr(EVP_MD_CTX);
  extern type ENGINE_PTR = c_ptr(ENGINE);

  extern proc OpenSSL_add_all_digests();
  extern proc EVP_get_digestbyname(name: c_string): EVP_MD_PTR;
  extern proc EVP_MD_CTX_init(ref ctx: EVP_MD_CTX): c_int;
  extern proc EVP_DigestInit_ex(ref ctx: EVP_MD_CTX, const types: EVP_MD_PTR, impl: ENGINE_PTR): c_int;
  extern proc EVP_DigestUpdate(ref ctx: EVP_MD_CTX, const d: c_void_ptr, cnt: size_t): c_int;
  extern proc EVP_DigestFinal_ex(ref ctx: EVP_MD_CTX, md: c_ptr(c_uchar), ref s: c_uint): c_int;

  /* Routine to handle OpenSSL primitives for creating digests */
  proc digestPrimitives(digestName: string, hashLen: int, inputBuffer: CryptoBuffer) {

    /* Loads the digest primitives into the table  */
    OpenSSL_add_all_digests();

    /* Create a context variable */
    var ctx: EVP_MD_CTX;

    /* Allocate space for hashed output */
    var hash: [0..hashLen-1] uint(8); ;
    var retHashLen: c_uint = 0;

    /* Get pointer to the desired digest structure */
    const md = EVP_get_digestbyname(digestName.c_str());

    /* OpenSSL primitive calls */
    EVP_MD_CTX_init(ctx);
    EVP_DigestInit_ex(ctx, md, c_nil: ENGINE_PTR);
    EVP_DigestUpdate(ctx, c_ptrTo(inputBuffer.buff): c_void_ptr, inputBuffer._len: size_t);
    EVP_DigestFinal_ex(ctx, c_ptrTo(hash): c_ptr(c_uchar), retHashLen);

    return hash;
  }
}
