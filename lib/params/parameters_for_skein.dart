library cipher.params.parameters_for_skein;

import "package:cipher/api.dart";

class ParametersForSkein implements CipherParameters {

  static const int Skein256 = 256;

  static const int Skein512 = 512;

  static const int Skein1024 = 1024;

  int _macSize;

  int _stateSize;

  CipherParameters _parameters;

  ParametersForSkein(this._parameters, this._stateSize, this._macSize);

  int get macSize => _macSize;

  int get stateSize => _stateSize;

  CipherParameters get parameters => _parameters;
}