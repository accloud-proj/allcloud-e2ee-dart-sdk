import 'dart:convert';

import 'package:accloud_e2ee/accloud_e2ee.dart';
import 'package:cryptography/cryptography.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

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

void main() {
  test('matches Java AAD and IV derivation', () {
    expect(
      utf8.decode(buildAad('session', 258, 1234, 'post', '/api/demo')),
      'sid=session&seq=258&ts=1234&m=POST&p=/api/demo',
    );
    expect(
      deriveIv(List<int>.generate(12, (index) => index), 258),
      [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 9],
    );
  });

  test('decodes the starter default Ed25519 PKIX public key', () {
    const key = 'MCowBQYDK2VwAyEAHOZKvD7vsMNDd2Kes2rl2i9WJmfU9LYIqoroYBQugK8=';
    expect(decodeEd25519PublicKey(key), hasLength(32));
  });

  test('performs signed handshake and bidirectional encrypted requests',
      () async {
    final fixture = await _ServerFixture.create();
    final client = AccloudE2eeClient(
      baseUri: Uri.parse('https://example.test/service'),
      trustedServerKeys: {'test-key': fixture.encodedSigningPublicKey},
      httpClient: MockClient(fixture.handle),
      clock: () => DateTime.fromMillisecondsSinceEpoch(1700000000000),
    );

    final postResponse = await client.post(
      '/api/echo',
      body: {'message': 'hello'},
      queryParameters: {'page': 1},
    );
    expect(postResponse.statusCode, 200);
    expect(jsonDecode(postResponse.body), {'accepted': true});
    expect(fixture.lastPlaintext, utf8.encode('{"message":"hello"}'));

    final getResponse = await client.get('/api/profile');
    expect(jsonDecode(getResponse.body), {'name': 'Accloud'});
    expect(fixture.lastClientSequence, 2);
    expect(client.hasActiveSession, isTrue);
    client.close();
  });
}

class _ServerFixture {
  _ServerFixture._({
    required this.signingKeyPair,
    required this.encodedSigningPublicKey,
    required this.serverKeyPair,
  });

  static Future<_ServerFixture> create() async {
    final signingKeyPair = await Ed25519().newKeyPairFromSeed(
      List<int>.generate(32, (index) => index + 1),
    );
    final signingPublicKey = await signingKeyPair.extractPublicKey();
    final serverKeyPair = await X25519().newKeyPair();
    return _ServerFixture._(
      signingKeyPair: signingKeyPair,
      encodedSigningPublicKey: base64.encode([
        ..._ed25519SpkiPrefix,
        ...signingPublicKey.bytes,
      ]),
      serverKeyPair: serverKeyPair,
    );
  }

  final SimpleKeyPair signingKeyPair;
  final String encodedSigningPublicKey;
  final SimpleKeyPair serverKeyPair;
  final serverNonce = List<int>.generate(16, (index) => 0xa0 + index);
  List<int>? _clientToServerKey;
  List<int>? _serverToClientKey;
  List<int>? _clientToServerIvBase;
  List<int>? _serverToClientIvBase;
  String? _sessionId;
  var _serverSequence = 0;
  int lastClientSequence = 0;
  List<int> lastPlaintext = const [];

  Future<http.Response> handle(http.Request request) async {
    if (request.url.path == '/e2ee/handshake') {
      return _handshake(request);
    }
    return _protectedRequest(request);
  }

  Future<http.Response> _handshake(http.Request httpRequest) async {
    final requestJson = jsonDecode(httpRequest.body) as Map<String, dynamic>;
    final request = HandshakeRequest(
      version: requestJson['version'] as String,
      clientEphemeralPubKey: requestJson['clientEphemeralPubKey'] as String,
      clientNonce: requestJson['clientNonce'] as String,
      ts: requestJson['ts'] as int,
      cipherSuites: (requestJson['cipherSuites'] as List).cast<String>(),
    );
    final serverPublicKey = await serverKeyPair.extractPublicKey();
    const sessionId = '00000000-0000-0000-0000-000000000001';
    var response = HandshakeResponse(
      version: e2eeVersion,
      sessionId: sessionId,
      serverEphemeralPubKey: encodeX25519PublicKey(serverPublicKey.bytes),
      serverNonce: base64UrlEncodeNoPadding(serverNonce),
      ts: 1700000000000,
      expireAt: 1700001800000,
      suite: e2eeCipherSuite,
      serverKeyId: 'test-key',
      signature: '',
    );
    final signature = await Ed25519().sign(
      utf8.encode(buildHandshakeSignaturePayload(request, response)),
      keyPair: signingKeyPair,
    );
    response = HandshakeResponse(
      version: response.version,
      sessionId: response.sessionId,
      serverEphemeralPubKey: response.serverEphemeralPubKey,
      serverNonce: response.serverNonce,
      ts: response.ts,
      expireAt: response.expireAt,
      suite: response.suite,
      serverKeyId: response.serverKeyId,
      signature: base64.encode(signature.bytes),
    );
    await _deriveKeys(request);
    _sessionId = sessionId;
    return http.Response(
      jsonEncode({
        'version': response.version,
        'sessionId': response.sessionId,
        'serverEphemeralPubKey': response.serverEphemeralPubKey,
        'serverNonce': response.serverNonce,
        'ts': response.ts,
        'expireAt': response.expireAt,
        'suite': response.suite,
        'serverKeyId': response.serverKeyId,
        'signature': response.signature,
      }),
      200,
      headers: {'content-type': 'application/json'},
    );
  }

  Future<void> _deriveKeys(HandshakeRequest request) async {
    final sharedSecret = await X25519().sharedSecretKey(
      keyPair: serverKeyPair,
      remotePublicKey: SimplePublicKey(
        decodeX25519PublicKey(request.clientEphemeralPubKey),
        type: KeyPairType.x25519,
      ),
    );
    final clientNonce = base64UrlDecodeNoPadding(request.clientNonce);
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
    _clientToServerKey = bytes.sublist(0, 32);
    _serverToClientKey = bytes.sublist(32, 64);
    _clientToServerIvBase = bytes.sublist(64, 76);
    _serverToClientIvBase = bytes.sublist(76, 88);
  }

  Future<http.Response> _protectedRequest(http.Request request) async {
    int clientSequence;
    if (request.bodyBytes.isEmpty) {
      expect(request.headers['x-e2ee-session-id'], _sessionId);
      clientSequence = int.parse(request.headers['x-e2ee-seq']!);
      lastPlaintext = const [];
    } else {
      final json = jsonDecode(request.body) as Map<String, dynamic>;
      final payload = EncryptedPayload.fromJson(json);
      clientSequence = payload.seq;
      final combined = base64UrlDecodeNoPadding(payload.ciphertext);
      final split = combined.length - 16;
      lastPlaintext = await AesGcm.with256bits().decrypt(
        SecretBox(
          combined.sublist(0, split),
          nonce: base64UrlDecodeNoPadding(payload.iv),
          mac: Mac(combined.sublist(split)),
        ),
        secretKey: SecretKey(_clientToServerKey!),
        aad: buildAad(
          _sessionId!,
          payload.seq,
          payload.ts,
          request.method,
          request.url.path,
        ),
      );
      expect(
        base64UrlDecodeNoPadding(payload.iv),
        deriveIv(_clientToServerIvBase!, payload.seq),
      );
    }
    expect(clientSequence, greaterThan(lastClientSequence));
    lastClientSequence = clientSequence;

    final cleartext = utf8.encode(
      request.url.path == '/api/profile'
          ? '{"name":"Accloud"}'
          : '{"accepted":true}',
    );
    final seq = ++_serverSequence;
    const ts = 1700000000000;
    final iv = deriveIv(_serverToClientIvBase!, seq);
    final box = await AesGcm.with256bits().encrypt(
      cleartext,
      secretKey: SecretKey(_serverToClientKey!),
      nonce: iv,
      aad: buildAad(_sessionId!, seq, ts, request.method, request.url.path),
    );
    return http.Response(
      jsonEncode({
        'sessionId': _sessionId,
        'seq': seq,
        'ts': ts,
        'iv': base64UrlEncodeNoPadding(iv),
        'ciphertext': base64UrlEncodeNoPadding([
          ...box.cipherText,
          ...box.mac.bytes,
        ]),
      }),
      200,
      headers: {'content-type': 'application/json'},
    );
  }
}
