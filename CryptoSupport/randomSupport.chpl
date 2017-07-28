require "openssl/rand.h";
require "CryptoSupport/CryptoUtils.chpl";

module randomSupport {

  extern proc RAND_bytes(buf: c_ptr(c_uchar), num: c_int): c_int;
  extern proc RAND_seed(const buf: c_void_ptr, num: c_int);

  proc randomize(buffLen: int) {
    var buff: [0..(buffLen - 1)] uint(8);
    RAND_bytes(c_ptrTo(buff): c_ptr(c_uchar), buffLen: c_int);
    return buff;
  }

}
