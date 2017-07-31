proc main(){
  use Crypto;
  use Crypto;

  var r = new CryptoRandom();
  var rBuff = r.createRandomBuffer(20);
  writeln(rBuff.toHex());
}
