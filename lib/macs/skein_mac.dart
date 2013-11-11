library cipher.macs.skein_mac;

import "package:cipher/api.dart";
import "package:cipher/digests/skein.dart";
import "package:cipher/params/key_parameter.dart";
import "package:cipher/params/parameters_for_skein.dart";
import "package:cipher/src/util.dart";
import "dart:typed_data";

class SkeinMac implements Mac {

  Skein _skein;
  Uint64List Xsave;

  SkeinMac() {}

  void init(CipherParameters params) {
    ParametersForSkein p = params as ParametersForSkein;
    KeyParameter kp = p.parameters as KeyParameter;

    _skein = new Skein.withKey(p.stateSize, p.macSize, 0, kp.key);
    Xsave = _skein.getstate();
  }

  String get algorithmName => _skein.algorithmName + "/MAC";

  int get macSize => _skein.digestSize;

  void updateByte(int inp) {
    _skein.updateByte(inp);
  }

  void update(Uint8List inp, int inpOff, int len) {
    _skein.update(inp, inpOff, len);
  }

  int doFinal(Uint8List out, int outOff) {
    int len = _skein.doFinal(out, outOff);
    reset();
    return len;
  }

  void reset() {
    _skein.initializeWithState(Xsave);
  }
}
