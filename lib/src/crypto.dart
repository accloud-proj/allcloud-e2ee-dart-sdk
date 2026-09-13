import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'constants.dart';
import 'exceptions.dart';
import 'models.dart';

const _x25519SpkiPrefix = <int>[
  0x30,
  0x2a,
  0x30,
  0x05,
  0x06,
  0x03,
  0x2b,
  0x65,
  0x6e,
  0x03,
  0x21,
  0x00,
];
const _ed25519SpkiPrefix = <int>[
  0x30,
  0x2a,
  0x30,
  0x05,
  0x06,
  0x03,
  0x2b,
  0x65,
  0x70,
  0x03,
  0x21,
  0x00,
];

String base64UrlEncodeNoPadding(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

Uint8List base64UrlDecodeNoPadding(String value) =>
    Uint8List.fromList(base64Url.decode(base64Url.normalize(value)));

Uint8List _decodePublicKey(String value) {
  final normalized = value
      .replaceAll(
          RegExp(r'-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----'), '')
      .replaceAll(RegExp(r'\s'), '');
  return Uint8List.fromList(base64.decode(base64.normalize(normalized)));
}

List<int> _unwrapSpki(List<int> encoded, List<int> prefix, String algorithm) {
  if (encoded.length != prefix.length + 32) {
    throw E2eeProtocolException('Invalid $algorithm public key length');
  }
  for (var index = 0; index < prefix.length; index++) {
    if (encoded[index] != prefix[index]) {
      throw E2eeProtocolException('Invalid $algorithm public key encoding');
    }
  }
  return encoded.sublist(prefix.length);
}

String encodeX25519PublicKey(List<int> rawPublicKey) {
  if (rawPublicKey.length != 32) {
    throw const E2eeProtocolException('X25519 public key must be 32 bytes');
  }
  return base64UrlEncodeNoPadding([..._x25519SpkiPrefix, ...rawPublicKey]);
}

List<int> decodeX25519PublicKey(String encoded) => _unwrapSpki(
      base64UrlDecodeNoPadding(encoded),
      _x25519SpkiPrefix,
      'X25519',
    );

List<int> decodeEd25519PublicKey(String encoded) =>
    _unwrapSpki(_decodePublicKey(encoded), _ed25519SpkiPrefix, 'Ed25519');

List<int> buildAad(
    String sessionId, int seq, int ts, String method, String path) {
  return utf8.encode(
    'sid=$sessionId&seq=$seq&ts=$ts&m=${method.toUpperCase()}&p=$path',
  );
}

List<int> deriveIv(List<int> ivBase, int seq) {
  if (ivBase.length != 12 || seq <= 0) {
    throw const E2eeProtocolException('Invalid IV base or sequence');
  }
  final iv = Uint8List.fromList(ivBase);
  var remaining = seq;
  for (var index = 0; index < 8; index++) {
    iv[iv.length - 1 - index] ^= remaining & 0xff;
    remaining ~/= 256;
  }
  return iv;
}

String buildHandshakeSignaturePayload(
  HandshakeRequest request,
  HandshakeResponse response,
) {
  return 'version=${response.version}\n'
      'sessionId=${response.sessionId}\n'
      'clientEphemeralPubKey=${request.clientEphemeralPubKey}\n'
      'clientNonce=${request.clientNonce}\n'
      'serverEphemeralPubKey=${response.serverEphemeralPubKey}\n'
      'serverNonce=${response.serverNonce}\n'
      'ts=${response.ts}\n'
      'expireAt=${response.expireAt}\n'
      'suite=${response.suite}\n'
      'serverKeyId=${response.serverKeyId}\n';
}

class E2eeSession {
  E2eeSession._({
    required this.sessionId,
    required this.expireAt,
    required SecretKey clientToServerKey,
    required SecretKey serverToClientKey,
    required List<int> clientToServerIvBase,
    required List<int> serverToClientIvBase,
  })  : _clientToServerKey = clientToServerKey,
        _serverToClientKey = serverToClientKey,
        _clientToServerIvBase = List.unmodifiable(clientToServerIvBase),
        _serverToClientIvBase = List.unmodifiable(serverToClientIvBase);

  final String sessionId;
  final int expireAt;
  final SecretKey _clientToServerKey;
  final SecretKey _serverToClientKey;
  final List<int> _clientToServerIvBase;
  final List<int> _serverToClientIvBase;
  final _aesGcm = AesGcm.with256bits();
  int _clientSequence = 0;
  final Set<int> _serverSequences = {};

  static Future<E2eeSession> create({
    required SimpleKeyPair clientKeyPair,
    required HandshakeResponse response,
    required List<int> clientNonce,
  }) async {
    final x25519 = X25519();
    final serverPublicKey = SimplePublicKey(
      decodeX25519PublicKey(response.serverEphemeralPubKey),
      type: KeyPairType.x25519,
    );
    final sharedSecret = await x25519.sharedSecretKey(
      keyPair: clientKeyPair,
      remotePublicKey: serverPublicKey,
    );
    final serverNonce = base64UrlDecodeNoPadding(response.serverNonce);
    final salt = (await Sha256().hash([...clientNonce, ...serverNonce])).bytes;
    final material = await Hkdf(
      hmac: Hmac.sha256(),
      outputLength: 88,
    ).deriveKey(
      secretKey: sharedSecret,
      nonce: salt,
      info: utf8.encode(e2eeHkdfInfo),
    );
    final bytes = await material.extractBytes();
    return E2eeSession._(
      sessionId: response.sessionId,
      expireAt: response.expireAt,
      clientToServerKey: SecretKey(bytes.sublist(0, 32)),
      serverToClientKey: SecretKey(bytes.sublist(32, 64)),
      clientToServerIvBase: bytes.sublist(64, 76),
      serverToClientIvBase: bytes.sublist(76, 88),
    );
  }

  int nextClientSequence() => ++_clientSequence;

  void destroy() {
    _clientToServerKey.destroy();
    _serverToClientKey.destroy();
  }

  Future<EncryptedPayload> encrypt(
    List<int> plaintext, {
    required int seq,
    required int ts,
    required String method,
    required String path,
  }) async {
    final iv = deriveIv(_clientToServerIvBase, seq);
    final secretBox = await _aesGcm.encrypt(
      plaintext,
      secretKey: _clientToServerKey,
      nonce: iv,
      aad: buildAad(sessionId, seq, ts, method, path),
    );
    return EncryptedPayload(
      sessionId: sessionId,
      seq: seq,
      ts: ts,
      iv: base64UrlEncodeNoPadding(iv),
      ciphertext: base64UrlEncodeNoPadding([
        ...secretBox.cipherText,
        ...secretBox.mac.bytes,
      ]),
    );
  }

  Future<List<int>> decrypt(
    EncryptedPayload payload, {
    required String method,
    required String path,
  }) async {
    if (payload.sessionId != sessionId ||
        payload.seq <= 0 ||
        _serverSequences.contains(payload.seq)) {
      throw const E2eeProtocolException('Invalid session or replayed response');
    }
    final expectedIv = deriveIv(_serverToClientIvBase, payload.seq);
    final iv = base64UrlDecodeNoPadding(payload.iv);
    if (!_constantTimeEquals(iv, expectedIv)) {
      throw const E2eeProtocolException('Invalid response IV');
    }
    final combined = base64UrlDecodeNoPadding(payload.ciphertext);
    if (combined.length < 16) {
      throw const E2eeProtocolException('Invalid AES-GCM ciphertext');
    }
    final split = combined.length - 16;
    try {
      final plaintext = await _aesGcm.decrypt(
        SecretBox(
          combined.sublist(0, split),
          nonce: iv,
          mac: Mac(combined.sublist(split)),
        ),
        secretKey: _serverToClientKey,
        aad: buildAad(sessionId, payload.seq, payload.ts, method, path),
      );
      _serverSequences.add(payload.seq);
      return plaintext;
    } on SecretBoxAuthenticationError catch (error) {
      throw E2eeProtocolException('Response authentication failed', error);
    }
  }
}

bool _constantTimeEquals(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}
