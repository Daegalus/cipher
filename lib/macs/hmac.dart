library cipher.macs.hmac;

import "package:cipher/api.dart";
import "package:cipher/params/key_parameter.dart";
import "package:cipher/src/util.dart";
import "dart:typed_data";

class HMac implements Mac {

  static const int IPAD = 0x36;
  static const int OPAD = 0x5C;

  Digest digest;
  int digestSize;
  int blockLength;

  Uint8List inputPad;
  Uint8List outputPad;

  static Map<String, int> blockLengths = {
    "GOST3411" : 32,
    "MD2"      : 16,
    "MD4"      : 64,
    "MD5"      : 64,

    "RIPEMD128": 64,
    "RIPEMD160": 64,

    "SHA-1"    : 64,
    "SHA-224"  : 64,
    "SHA-256"  : 64,
    "SHA-384"  : 128,
    "SHA-512"  : 128,

    "Tiger"    : 64,
    "Whirlpool": 64
  };

  String get algorithmName => "MAC";

  int get macSize => digestSize;

  static int _getByteLength(Digest digest) {
    int  b = blockLengths[digest.algorithmName];

    if (b == null) {
      throw new ArgumentError("unknown digest passed: " + digest.algorithmName);
    }

    return b;
  }

  HMac(this.digest, [byteLength]) {
    digestSize = digest.digestSize;

    this.blockLength = byteLength == null ? _getByteLength(digest) : byteLength;

    inputPad = new Uint8List(blockLength);
    outputPad = new Uint8List(blockLength);
  }

  void init( CipherParameters params ) {
    digest.reset();

    Uint8List key = (params as KeyParameter).key;

    if (key.length > blockLength) {
      digest.update(key, 0, key.length);
      digest.doFinal(inputPad, 0);
      for (int i = digestSize; i < inputPad.length; i++)
      {
        inputPad[i] = 0;
      }
    } else {
      inputPad.setRange(0, key.length, key);
      for (int i = key.length; i < inputPad.length; i++) {
        inputPad[i] = 0;
      }
    }

    outputPad = new Uint8List(inputPad.length);
    outputPad.setRange(0, inputPad.length, inputPad);

    for (int i = 0; i < inputPad.length; i++) {
      inputPad[i] ^= IPAD;
    }

    for (int i = 0; i < outputPad.length; i++) {
      outputPad[i] ^= OPAD;
    }

    digest.update(inputPad, 0, inputPad.length);
  }

  void updateByte(int inp) {
    digest.updateByte(inp);
  }

  void update( Uint8List inp, int inpOff, int len ) {
    digest.update(inp, inpOff, len);
  }

  int doFinal( Uint8List out, int outOff ) {
    Uint8List tmp = new Uint8List(digestSize);
    digest.doFinal(tmp, 0);

    digest.update(outputPad, 0, outputPad.length);
    digest.update(tmp, 0, tmp.length);

    int len = digest.doFinal(out, outOff);

    reset();

    return len;
  }

  void reset() {
    digest.reset();
    digest.update(inputPad, 0, inputPad.length);
  }
}
