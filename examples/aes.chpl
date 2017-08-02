proc main(){
  use Crypto;
  use Crypto;
  use KDF;
  use KDF;

  /* Create AES instance with the version required */
  var a = new AES(256, "cbc");

  /* Key Generation phase */
  var salt = new CryptoBuffer("random_salt");
  var hash = new Hash("SHA256");

  var k = KDF.PBKDF2_HMAC("random_key", salt, a.getByteSize(), 1000, hash);
  writeln("Generated Key: ", k.toHex());

  var iv = (new CryptoRandom()).createRandomBuffer(32); // or use a.getByteSize() as the argument
  writeln("Generated IV: ", iv.toHex());

  /* Message to be encrypted */
  var msg = new CryptoBuffer("foo_bar");
  writeln("Original Message: ", msg.toHex());

  /* Encrypt the message using the key and IV */
  var ct = a.encrypt(msg, k, iv);
  writeln("Obtained Ciphertext: ", ct.toHex());

  /* Decrypt the message using the key and IV */
  var orig = a.decrypt(ct, k, iv);
  writeln("Obtaineds Plaintext: ", orig.toHex());
}
