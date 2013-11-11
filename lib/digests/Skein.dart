library cipher.digests.skein_mac;

import "package:cipher/api.dart";
import "package:cipher/engines/threefish.dart";
import "package:cipher/params/key_parameter.dart";
import "package:cipher/src/util.dart";
import "dart:typed_data";

class Skein implements Digest {

  static const int NORMAL = 0;

  static const int ZEROED_STATE = 1;

  static const int CHAINED_STATE = 2;

  static const int CHAINED_CONFIG = 3;

  final Uint8List schema = new Uint8List.fromList([83, 72, 65, 51]); // "SHA3"

  Threefish _cipher;

  int _cipherStateBits;

  int cipherStateBytes;

  int _cipherStateWords;

  int _outputBytes;

  Uint8List _inputBuffer;

  int _bytesFilled;

  Uint64List _cipherInput;

  Uint64List _state;

  int _hashSize;

  SkeinConfig _configuration;

  UbiTweak ubiParameters;

  int get stateSize => _cipherStateBits;

  String get algorithmName => "Skein";

  int get digestSize => _outputBytes;

  Skein(int stateSize, int outputSize) {
    _setup(stateSize, outputSize);

    // Generate the configuration string
    _configuration = new SkeinConfig(this);
    _configuration.setSchema(schema); // "SHA3"
    _configuration.setVersion(1);
    _configuration.generateConfiguration();
    initialize();
  }

  Skein.withKey(int stateSize, int outputSize, int treeInfo, Uint8List key) {
    _setup(stateSize, outputSize);

    /* compute the initial chaining state values, based on key */
    if (key.length > 0) {
      /* is there a key? */
      _outputBytes = cipherStateBytes;
      ubiParameters.startNewBlockType(UbiTweak.Key);
      update(key, 0, key.length); /* hash the key */
      Uint8List preHash = finalPad();

      /* copy over into state variables */
      for (int i = 0; i < _cipherStateWords; i++)
        _state[i] = ByteLong.GetUInt64(preHash, i * 8);
    }
    /*
     * build/process the config block, type == CONFIG (could be precomputed
     * for each key)
     */
    _outputBytes = (outputSize + 7) ~/ 8;

    _configuration = new SkeinConfig(this);
    _configuration.setSchema(schema); // "SHA3"
    _configuration.setVersion(1);

    initializeWithType(CHAINED_CONFIG);
  }

  void _setup(int stateSize, int outputSize) {
    // Make sure the output bit size > 0
    if (outputSize <= 0)throw new ArgumentError("Skein: Output bit size must be greater than zero.");

    _cipherStateBits = stateSize;
    cipherStateBytes = stateSize ~/ 8;
    _cipherStateWords = stateSize ~/ 64;

    _hashSize = outputSize;
    _outputBytes = (outputSize + 7) ~/ 8;

    // Figure out which cipher we need based on
    // the state size
    _cipher = Threefish.createCipher(stateSize);
    if (_cipher == null)throw new ArgumentError("Skein: Unsupported state size.");

    // Allocate buffers
    _inputBuffer = new Uint8List(cipherStateBytes);
    _cipherInput = new Uint64List(_cipherStateWords);
    _state = new Uint64List(_cipherStateWords);

    // Allocate tweak
    ubiParameters = new UbiTweak();
  }

  void processBlock(int bytes) {
    // Set the key to the current state
    _cipher.setKey(_state);

    // Update tweak
    ubiParameters.addBytesProcessed(bytes);

    _cipher.tweak = ubiParameters.tweak;

    // Encrypt block
    _cipher.encrypt(_cipherInput, _state);

    // Feed-forward input with state
    for (int i = 0; i < _cipherInput.length; i++)
      _state[i] ^= _cipherInput[i];
  }

  void reset() {
    initialize();
  }

  void updateByte(int inp) {
    Uint8List tmp = new Uint8List.fromList([inp]);
    update(tmp, 0, 1);
  }

  void update(Uint8List inp, int inpOff, int len) {
    int bytesDone = 0;

    // Fill input buffer
    while (bytesDone < len) {
      // Do a transform if the input buffer is filled
      if (_bytesFilled == cipherStateBytes) {
        // Copy input buffer to cipher input buffer
        inputBufferToCipherInput();

        // Process the block
        processBlock(cipherStateBytes);

        // Clear first flag, which will be set
        // by Initialize() if this is the first transform
        ubiParameters.firstBlock = false;

        // Reset buffer fill count
        _bytesFilled = 0;
      }
      _inputBuffer[_bytesFilled++] = inp[inpOff++];
      bytesDone++;
    }
  }

  void updateBits(Uint8List inp, int inpOff, int len) {
    if (ubiParameters.isBitPad()) {
      throw new StateError("Skein: partial byte only on last data block");
    }
    // if number of bits is a multiple of bytes - that's easy
    if ((len & 0x7) == 0) {
      update(inp, inpOff, len >> 3);
      return;
    }
    // Fill in bytes in buffer, add one for partial byte
    update(inp, inpOff, (len >> 3) + 1);

    // Mask partial byte and set BitPad flag before doFinal()
    int mask = (1 << (7 - (len & 7))); // partial byte bit mask
    _inputBuffer[_bytesFilled - 1] = ((_inputBuffer[_bytesFilled - 1] & (0 - mask)) | mask);
    ubiParameters.bitPad = true;
  }

  Uint8List doFinalBytes() {
    int i;

    // Pad left over space in input buffer with zeros
    // and copy to cipher input buffer
    for (i = _bytesFilled; i < _inputBuffer.length; i++)
      _inputBuffer[i] = 0;

    inputBufferToCipherInput();

    // Do final message block
    ubiParameters.finalBlock = true;
    processBlock(_bytesFilled);

    // Clear cipher input
    for (i = 0; i < _cipherInput.length; i++)
      _cipherInput[i] = 0;

    // Do output block counter mode output
    int j;

    Uint8List hash = new Uint8List(_outputBytes);
    Uint64List oldState = new Uint64List(_cipherStateWords);

    // Save old state
    for (j = 0; j < _state.length; j++)
      oldState[j] = _state[j];

    for (i = 0; i < _outputBytes; i += cipherStateBytes) {
      ubiParameters.startNewBlockType(UbiTweak.Out);
      ubiParameters.finalBlock = true;
      processBlock(8);

      // Output a chunk of the hash
      int outputSize = _outputBytes - i;
      if (outputSize > cipherStateBytes)outputSize = cipherStateBytes;

      ByteLong.PutBytes(_state, hash, i, outputSize);

      // Restore old state
      for (j = 0; j < _state.length; j++)
        _state[j] = oldState[j];

      // Increment counter
      _cipherInput[0]++;
    }
    reset();
    return hash;
  }

  int doFinal(Uint8List out, int outOff) {
    Uint8List hash = doFinalBytes();
    out.setRange(outOff, hash.length, hash);
    return hash.length;
  }

  Uint8List finalPad() {
    int i;

    // Pad left over space in input buffer with zeros
    // and copy to cipher input buffer
    for (i = _bytesFilled; i < _inputBuffer.length; i++)
      _inputBuffer[i] = 0;

    inputBufferToCipherInput();

    // Do final message block
    ubiParameters.finalBlock = true;
    processBlock(_bytesFilled);

    Uint8List data = new Uint8List(_outputBytes);

    for (i = 0; i < _outputBytes; i += cipherStateBytes) {
      // Output a chunk of the hash
      int outputSize = _outputBytes - i;
      if (outputSize > cipherStateBytes)outputSize = cipherStateBytes;

      ByteLong.PutBytes(_state, data, i, outputSize);
    }
    return data;
  }

  void initializeWithType(int initializationType) {
    switch (initializationType) {
      case NORMAL:
        // Normal initialization
        initialize();
        return;

      case ZEROED_STATE:
        // Start with a all zero state
        for (int i = 0; i < _state.length; i++)
          _state[i] = 0;
        break;

      case CHAINED_STATE:
        // Keep the state as it is and do nothing
        break;

      case CHAINED_CONFIG:
        // Generate a chained configuration
        _configuration.generateConfigurationWithIntiialState(_state);
        // Continue initialization
        initialize();
        return;
    }

    // Reset bytes filled
    _bytesFilled = 0;
  }

  void initialize() {
    // Copy the configuration value to the state
    for (int i = 0; i < _state.length; i++)
      _state[i] = _configuration.ConfigValue[i];

    // Set up tweak for message block
    ubiParameters.startNewBlockType(UbiTweak.Message);

    // Reset bytes filled
    _bytesFilled = 0;
  }

  void initializeWithState(Uint64List externalState) {
    // Copy an external saved state value to internal state
    for (int i = 0; i < _state.length; i++)
      _state[i] = externalState[i];

    // Set up tweak for message block
    ubiParameters.startNewBlockType(UbiTweak.Message);

    // Reset bytes filled
    _bytesFilled = 0;
  }

  void inputBufferToCipherInput() {
    for (int i = 0; i < _cipherStateWords; i++)
      _cipherInput[i] = ByteLong.GetUInt64(_inputBuffer, i * 8);
  }

  int get cipherStateBits => _cipherStateBits;

  int get hashSize => _hashSize;

  int get byteLength => cipherStateBytes;

  Uint64List getstate() {
    Uint64List s = new Uint64List(_state.length);
    // Copy state values to external state
    for (int i = 0; i < _state.length; i++)
      s[i] = _state[i];
    return s;
  }
}


class SkeinConfig {
  int stateSize;

  Uint64List ConfigValue;

  // Set the state size for the configuration
  Uint64List ConfigString;

  SkeinConfig(Skein sourceHash) {
    stateSize = sourceHash.cipherStateBits;

    // Allocate config value
    ConfigValue = new Uint64List(stateSize ~/ 64);

    // Set the state size for the configuration
    ConfigString = new Uint64List(ConfigValue.length);
    ConfigString[1] = sourceHash.hashSize;
  }

  void generateConfiguration() {
    Threefish cipher = Threefish.createCipher(stateSize);
    UbiTweak tweak = new UbiTweak();

    // Initialize the tweak value
    tweak.startNewBlockType(UbiTweak.Config);
    tweak.finalBlock = true;
    tweak.bitsProcessed = 32;

    cipher.tweak = tweak.tweak;
    cipher.encrypt(ConfigString, ConfigValue);

    ConfigValue[0] ^= ConfigString[0];
    ConfigValue[1] ^= ConfigString[1];
    ConfigValue[2] ^= ConfigString[2];
  }

  void generateConfigurationWithIntiialState(Uint64List initialState) {
    Threefish cipher = Threefish.createCipher(stateSize);
    UbiTweak tweak = new UbiTweak();

    // Initialize the tweak value
    tweak.startNewBlockType(UbiTweak.Config);
    tweak.finalBlock = true;
    tweak.bitsProcessed = 32;

    cipher.setKey(initialState);
    cipher.tweak = tweak.tweak;
    cipher.encrypt(ConfigString, ConfigValue);

    ConfigValue[0] ^= ConfigString[0];
    ConfigValue[1] ^= ConfigString[1];
    ConfigValue[2] ^= ConfigString[2];
  }

  void setSchema(Uint8List schema) {
    if (schema.length != 4)throw new ArgumentError("Skein configuration: Schema must be 4 bytes.");

    int n = ConfigString[0];

    // Clear the schema bytes
    n &= ~0xffffffff;
    // Set schema bytes
    n |= schema[3] << 24;
    n |= schema[2] << 16;
    n |= schema[1] << 8;
    n |= schema[0];

    ConfigString[0] = n;
  }

  void setVersion(int version) {
    if (version < 0 || version > 3)throw new ArgumentError("Skein configuration: Version must be between 0 and 3, inclusive.");

    ConfigString[0] &= ~(0x03 << 32);
    ConfigString[0] |= version << 32;
  }

  void setTreeLeafSize(int size) {
    ConfigString[2] &= ~0xff;
    ConfigString[2] |= size;
  }

  void setTreeFanOutSize(int size) {
    ConfigString[2] &= ~(0xff << 8);
    ConfigString[2] |= size << 8;
  }

  void setMaxTreeHeight(int height) {
    if (height == 1)throw new ArgumentError("Skein configuration: Tree height must be zero or greater than 1.");

    ConfigString[2] &= ~(0xff << 16);
    ConfigString[2] |= height << 16;
  }
}


class UbiTweak {

  static const int Key = 0, Config = 4, Personalization = 8, PublicKey = 12, KeyIdentifier = 16, Nonce = 20, Message = 48, Out = 63;

  static const int _T1FlagFinal = 1 << 63;

  static const int _T1FlagFirst = 1 << 62;

  static const int _T1FlagBitPad = 1 << 55;

  Uint64List tweak = new Uint64List(2);

  UbiTweak() {
  }

  bool isFirstBlock() {
    return (tweak[1] & _T1FlagFirst) != 0;
  }
  set firstBlock(bool value) =>  value ? tweak[1] |= _T1FlagFirst : tweak[1] &= ~_T1FlagFirst;

  bool isFinalBlock() {
    return (tweak[1] & _T1FlagFinal) != 0;
  }
  set finalBlock(bool value) => value ? tweak[1] |= _T1FlagFinal : tweak[1] &= ~_T1FlagFinal;

  bool isBitPad() {
    return (tweak[1] & _T1FlagBitPad) != 0;
  }
  set bitPad(bool value) => value ? tweak[1] |= _T1FlagBitPad : tweak[1] &= ~_T1FlagBitPad;

  int get treeLevel => ((tweak[1] >> 48) & 0x7f);
      set treeLevel(int value) => _setTreeLevel(value);

  void _setTreeLevel(int value) {
    if (value > 63) throw new Exception("Tree level must be between 0 and 63, inclusive.");

    tweak[1] &= ~(0x7f << 48);
    tweak[1] |= value << 48;
  }

  Uint8List get bitsProcessed => _getBitsProcessed();
  Uint8List _getBitsProcessed() {
    Uint8List retval = new Uint8List(2);
    retval[0] = tweak[0];
    retval[1] = tweak[1] & 0xffffffff;
    return retval;
  }
  set bitsProcessed(int value) => _setBitsProcessed(value);
  void _setBitsProcessed(int value) {
    tweak[0] = value;
    tweak[1] &= 0xffffffff00000000;
  }

  /**
   * Add number of processed bytes.
   *
   * Adds the integere value to the 96-bit field of processed
   * bytes.
   *
   * @param value
   *        Number of processed bytes.
   */

  void addBytesProcessed(int value) {
    final int len = 3;
    int carry = value;

    Uint64List words = new Uint64List(len);
    words[0] = tweak[0] & 0xffffffff;
    words[1] = ((tweak[0] >> 32) & 0xffffffff);
    words[2] = (tweak[1] & 0xffffffff);

    for (int i = 0; i < len; i++) {
      carry += words[i];
      words[i] = carry;
      carry >>= 32;
    }
    tweak[0] = words[0] & 0xffffffff;
    tweak[0] |= (words[1] & 0xffffffff) << 32;
    tweak[1] |= words[2] & 0xffffffff;
  }

  /**
   * Get the current UBI block type.
   */
  int get blockType => ((tweak[1] >> 56) & 0x3f);
      set blockType(int value) => tweak[1] = value << 56;

  /**
   * Starts a new UBI block type by setting BitsProcessed to zero, setting
   * the first flag, and setting the block type.
   *
   * @param type
   *     The UBI block type of the new block
   */

  void startNewBlockType(int type) {
    bitsProcessed = 0;
    blockType = type;
    firstBlock = true;
  }
}