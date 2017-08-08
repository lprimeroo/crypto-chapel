proc main() {
  use Crypto;
  use Crypto;

  var r = new RSA(2048);
  var msg = new CryptoBuffer("hello_world");
  writeln("MESSAGE: " + msg.toHexString());

  var envp = r.encrypt(msg);
  writeln("ENC_KEY_USING_RSA: " + envp.getEncKey().toHexString());
  writeln("ENC_MSG_USING_AES: " + envp.getEncMessage().toHexString());
  writeln("GENERATED_IV: " + envp.getIV().toHexString());

  var pt = r.decrypt(envp);
  writeln("DECRYPTED_MESSAGE: " + pt.toHexString());
}
