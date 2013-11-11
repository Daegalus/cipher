library cipher.params.parameters_for_threefish;

import "dart:typed_data";

import "package:cipher/api.dart";

class ParametersForThreefish implements CipherParameters {
  static const int Threefish256 = 256;

  static const int Threefish512 = 512;

  static const int Threefish1024 = 1024;

  int _stateSize;

  CipherParameters _parameters;

  Uint64List tweak;

  ParametersForThreefish(CipherParameters parameters, int stateSize, Uint64List tweak) {
    _stateSize = stateSize;
    _parameters = parameters;
    if (tweak != null) {
      this.tweak = new Uint64List(2);
      this.tweak[0] = tweak[0];
      this.tweak[1] = tweak[1];
    }
  }

  int get stateSize => _stateSize;

  CipherParameters get parameters => _parameters;
}