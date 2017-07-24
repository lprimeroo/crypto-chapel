proc main(){
  use Crypto;
  use Crypto;

  var a = new AES(256, "cbc");
  var salt = new CryptoBuffer("random_salt");
  var k = a.generateKey("random_key", salt);
  writeln("Generated Key: ", k.toHex());
  var iv = a.generateIV();
  writeln("Generated IV: ", iv.toHex());

  var msg = new CryptoBuffer("foo_bar");
  writeln("Original Message: ", msg.toHex());
  var ct = a.encrypt(msg, k, iv);
  writeln("Obtained Ciphertext: ", ct.toHex());

  var orig = a.decrypt(ct, k, iv);
  writeln("Obtaineds Plaintext: ", orig.toHex());
}
