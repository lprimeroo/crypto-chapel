proc main(){
  use Crypto;
  use Crypto;

  /* String to buffer */
  var b = new CryptoBuffer("foobar");
  writeln(b.toHex());
  writeln(b.toHexString());
  writeln(b.getBuffData());
  writeln(b.getBuffSize());

  /* Array to buffer */
  var arr: [0..4] uint(8) = [1, 2, 3, 4, 5];
  var c = new CryptoBuffer(arr);
  writeln(c.toHex());
  writeln(c.toHexString());
  writeln(c.getBuffData());
  writeln(c.getBuffSize());
}
