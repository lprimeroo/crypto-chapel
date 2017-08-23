proc main(){
  use Crypto;

  /* Create AES instance with the version required */
  var a = new AES(256, "cbc");

  /* Key Generation phase starts */

  /* Generate custom salt for the key. Use CryptoRandom for random generation */
  var salt = new CryptoBuffer("random_salt");

  /* Hash to be used for key generation */
  var hash = new Hash("SHA256");

  /* Create a KDF object with key size, iteration count and hash object as parameter */
  var k = new KDF(a.getByteSize(), 1000, hash);

  /* Call the Password Based KDF 2 (PBKDF2) method for key generations.
  Multiple KDFs to eb supported in the future. */
  var key = k.PBKDF2_HMAC("random_key", salt);
  writeln("Generated Key: ", key.toHex());

  /* Key Generation phase ends */

  /* Random generation of the Initialization Vector. A custom IV can also be created
  usng CryptoBuffer */
  var iv = (new CryptoRandom()).createRandomBuffer(32); // or use a.getByteSize() as the argument
  writeln("Generated IV: ", iv.toHex());

  /* The message to be encrypted */
  var msg = new CryptoBuffer("foo_bar");
  writeln("Original Message: ", msg.toHex());

  /* Encrypt the message using the key and IV */
  var ct = a.encrypt(msg, key, iv);
  writeln("Obtained Ciphertext: ", ct.toHex());

  /* Decrypt the message using the key and IV */
  var orig = a.decrypt(ct, key, iv);
  writeln("Obtaineds Plaintext: ", orig.toHex());
}
