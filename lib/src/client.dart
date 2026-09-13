import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:http/http.dart' as http;

import 'constants.dart';
import 'crypto.dart';
import 'exceptions.dart';
import 'models.dart';

typedef Clock = DateTime Function();

class AccloudE2eeClient {
  AccloudE2eeClient({
    required this.baseUri,
    required this.trustedServerKeys,
    this.handshakePath = '/e2ee/handshake',
    http.Client? httpClient,
    Clock? clock,
  })  : _httpClient = httpClient ?? http.Client(),
        _clock = clock ?? DateTime.now;

  final Uri baseUri;
  final Map<String, String> trustedServerKeys;
  final String handshakePath;
  final http.Client _httpClient;
  final Clock _clock;
  E2eeSession? _session;
  Future<void>? _handshakeFuture;

  String? get sessionId => _session?.sessionId;
  bool get hasActiveSession =>
      _session != null && _session!.expireAt > _clock().millisecondsSinceEpoch;

  Future<void> handshake({bool force = false}) async {
    if (!force && hasActiveSession) return;
    final pending = _handshakeFuture;
    if (pending != null) return pending;

    final operation = _performHandshake();
    _handshakeFuture = operation;
    try {
      await operation;
    } finally {
      if (identical(_handshakeFuture, operation)) {
        _handshakeFuture = null;
      }
    }
  }

  Future<void> _performHandshake() async {
    final x25519 = X25519();
    final keyPair = await x25519.newKeyPair();
    final publicKey = await keyPair.extractPublicKey();
    final nonceKey = SecretKeyData.random(length: 16);
    final clientNonce = List<int>.of(await nonceKey.extractBytes());
    nonceKey.destroy();
    final request = HandshakeRequest(
      version: e2eeVersion,
      clientEphemeralPubKey: encodeX25519PublicKey(publicKey.bytes),
      clientNonce: base64UrlEncodeNoPadding(clientNonce),
      ts: _clock().millisecondsSinceEpoch,
      cipherSuites: const [e2eeCipherSuite],
    );

    final http.Response httpResponse;
    try {
      httpResponse = await _httpClient.post(
        _resolve(handshakePath),
        headers: const {'content-type': 'application/json'},
        body: jsonEncode(request.toJson()),
      );
    } catch (error) {
      keyPair.destroy();
      throw E2eeHandshakeException('Handshake request failed', error);
    }
    if (httpResponse.statusCode < 200 || httpResponse.statusCode >= 300) {
      keyPair.destroy();
      throw E2eeHandshakeException(
        'Handshake failed with HTTP ${httpResponse.statusCode}',
      );
    }

    try {
      final json = jsonDecode(utf8.decode(httpResponse.bodyBytes));
      if (json is! Map<String, dynamic>) {
        throw const FormatException('Handshake response must be an object');
      }
      final response = HandshakeResponse.fromJson(json);
      await _validateHandshake(request, response);
      _session = await E2eeSession.create(
        clientKeyPair: keyPair,
        response: response,
        clientNonce: clientNonce,
      );
    } on E2eeException {
      rethrow;
    } catch (error) {
      throw E2eeHandshakeException('Invalid handshake response', error);
    } finally {
      keyPair.destroy();
    }
  }

  Future<http.Response> request(
    String method,
    String path, {
    Object? body,
    Map<String, String>? headers,
    Map<String, dynamic>? queryParameters,
  }) async {
    await handshake();
    final session = _session!;
    final uri = _resolve(path).replace(
      queryParameters: queryParameters?.map(
        (key, value) => MapEntry(key, value?.toString()),
      ),
    );
    final requestHeaders = <String, String>{...?headers};
    final seq = session.nextClientSequence();
    final ts = _clock().millisecondsSinceEpoch;
    final plaintext = _encodeBody(body);
    Object? requestBody;

    if (plaintext.isEmpty) {
      requestHeaders.addAll({
        'X-E2EE-Session-Id': session.sessionId,
        'X-E2EE-Seq': '$seq',
        'X-E2EE-Ts': '$ts',
      });
    } else {
      final payload = await session.encrypt(
        plaintext,
        seq: seq,
        ts: ts,
        method: method,
        path: uri.path,
      );
      requestHeaders['content-type'] = 'application/json';
      requestBody = jsonEncode(payload.toJson());
    }

    final response = http.Request(method.toUpperCase(), uri)
      ..headers.addAll(requestHeaders)
      ..body = requestBody?.toString() ?? '';
    final streamed = await _httpClient.send(response);
    final encryptedBytes = await streamed.stream.toBytes();
    final Object? encryptedJson;
    try {
      encryptedJson = jsonDecode(utf8.decode(encryptedBytes));
    } catch (error) {
      throw E2eeProtocolException('Invalid encrypted response JSON', error);
    }
    if (encryptedJson is! Map<String, dynamic> ||
        !encryptedJson.containsKey('ciphertext')) {
      if (streamed.statusCode == 401 || streamed.statusCode == 403) {
        clearSession();
        return http.Response.bytes(
          encryptedBytes,
          streamed.statusCode,
          headers: streamed.headers,
          reasonPhrase: streamed.reasonPhrase,
          request: response,
        );
      }
      throw const E2eeProtocolException('Encrypted response must be an object');
    }
    final payload = EncryptedPayload.fromJson(encryptedJson);
    final plaintextResponse = await session.decrypt(
      payload,
      method: method,
      path: uri.path,
    );
    return http.Response.bytes(
      plaintextResponse,
      streamed.statusCode,
      headers: streamed.headers,
      reasonPhrase: streamed.reasonPhrase,
      request: response,
    );
  }

  Future<http.Response> get(
    String path, {
    Map<String, String>? headers,
    Map<String, dynamic>? queryParameters,
  }) =>
      request(
        'GET',
        path,
        headers: headers,
        queryParameters: queryParameters,
      );

  Future<http.Response> post(
    String path, {
    Object? body,
    Map<String, String>? headers,
    Map<String, dynamic>? queryParameters,
  }) =>
      request(
        'POST',
        path,
        body: body,
        headers: headers,
        queryParameters: queryParameters,
      );

  Future<void> _validateHandshake(
    HandshakeRequest request,
    HandshakeResponse response,
  ) async {
    if (response.version != e2eeVersion || response.suite != e2eeCipherSuite) {
      throw const E2eeHandshakeException(
          'Unsupported protocol or cipher suite');
    }
    final now = _clock().millisecondsSinceEpoch;
    if (response.expireAt <= now || response.ts > response.expireAt) {
      throw const E2eeHandshakeException('Handshake response has expired');
    }
    final encodedKey = trustedServerKeys[response.serverKeyId];
    if (encodedKey == null) {
      throw E2eeHandshakeException(
        'Untrusted server key ID: ${response.serverKeyId}',
      );
    }
    final publicKey = SimplePublicKey(
      decodeEd25519PublicKey(encodedKey),
      type: KeyPairType.ed25519,
    );
    final signature = Signature(
      base64.decode(response.signature),
      publicKey: publicKey,
    );
    final valid = await Ed25519().verify(
      utf8.encode(buildHandshakeSignaturePayload(request, response)),
      signature: signature,
    );
    if (!valid) {
      throw const E2eeHandshakeException('Invalid server handshake signature');
    }
  }

  List<int> _encodeBody(Object? body) {
    if (body == null) return const [];
    if (body is List<int>) return body;
    if (body is String) return utf8.encode(body);
    return utf8.encode(jsonEncode(body));
  }

  Uri _resolve(String path) {
    final base = baseUri.toString().endsWith('/')
        ? baseUri
        : baseUri.replace(
            path: '${baseUri.path}/',
          );
    return base.resolve(path);
  }

  void clearSession() {
    _session?.destroy();
    _session = null;
  }

  void close() {
    clearSession();
    _httpClient.close();
  }
}
