# Accloud E2EE Dart SDK

[English](README.md) | [简体中文](README.zh-CN.md)

A Dart and Flutter client SDK for communicating with APIs protected by
`accloud-e2ee-spring-boot-starter`.

## Features

- X25519 ephemeral key agreement
- HKDF-SHA256 session key derivation
- AES-256-GCM request and response encryption
- Ed25519 server handshake signature verification
- Independent client-to-server and server-to-client keys and IVs
- Request and response replay protection
- Support for Android, iOS, Web, desktop, and the Dart VM

The current protocol version is `1`, using the cipher suite
`X25519+HKDF-SHA256+AES-256-GCM+Ed25519`.

## Installation

Until the package is published to pub.dev, add the Git dependency:

```yaml
dependencies:
  accloud_e2ee:
    git:
      url: https://github.com/accloud-proj/allcloud-e2ee-dart-sdk.git
      ref: main
```

Then install dependencies:

```shell
flutter pub get
```

For a Dart-only application, use `dart pub get` instead.

## Server Requirements

The Spring Boot application must expose an E2EE handshake endpoint and exclude
it from the encryption filter:

```yaml
accloud.e2ee.enabled: true
accloud.e2ee.protected-path-prefixes: [/api/**]
accloud.e2ee.bypass-paths: [/e2ee/handshake]
accloud.e2ee.sign-key-id: accloud-e2ee-ed25519-1
accloud.e2ee.sign-private-key: ${E2EE_SIGN_PRIVATE_KEY}
accloud.e2ee.sign-public-key: ${E2EE_SIGN_PUBLIC_KEY}
```

The handshake endpoint should delegate to `E2eeHandshakeService`:

```java
@PostMapping("/e2ee/handshake")
public HandshakeResponse handshake(@RequestBody HandshakeRequest request) {
    return handshakeService.handshake(request);
}
```

The returned `serverKeyId` must match an entry in the client's
`trustedServerKeys` map.

## Quick Start

Create one client and reuse it for API calls. Do not create a new client for
every request because the client owns the E2EE session and sequence numbers.

```dart
import 'dart:convert';

import 'package:accloud_e2ee/accloud_e2ee.dart';

final e2eeClient = AccloudE2eeClient(
  baseUri: Uri.parse('https://api.example.com'),
  trustedServerKeys: const {
    'accloud-e2ee-ed25519-1': '''
-----BEGIN PUBLIC KEY-----
REPLACE_WITH_SERVER_ED25519_PUBLIC_KEY
-----END PUBLIC KEY-----
''',
  },
);

Future<Map<String, dynamic>> loadProfile() async {
  final response = await e2eeClient.get('/api/profile');
  if (response.statusCode != 200) {
    throw StateError('Request failed: ${response.statusCode}');
  }
  return jsonDecode(response.body) as Map<String, dynamic>;
}
```

The trusted Ed25519 public key may be an X.509/PKIX PEM string or its standard
Base64-encoded DER content. Distribute this key through a trusted channel and
embed it in the application. Never download the trust key from the handshake
endpoint itself.

## Making Requests

### GET Request

Requests without a body automatically send the session ID, sequence number,
and timestamp in `X-E2EE-*` headers. Query parameters are not included in the
AAD, matching the Spring Boot implementation.

```dart
final response = await e2eeClient.get(
  '/api/messages',
  queryParameters: {'page': 1, 'size': 20},
  headers: {'authorization': 'Bearer $accessToken'},
);

final data = jsonDecode(response.body);
```

### JSON POST Request

Maps and other JSON-encodable objects are encoded as UTF-8 JSON before
encryption:

```dart
final response = await e2eeClient.post(
  '/api/messages',
  body: {
    'recipientId': 'user-1001',
    'text': 'Hello',
  },
  headers: {'authorization': 'Bearer $accessToken'},
);
```

The `body` parameter accepts a JSON-encodable object, a UTF-8 `String`, raw
`List<int>` bytes, or `null` for an empty body.

### Other HTTP Methods

Use `request()` for PUT, PATCH, DELETE, or another method:

```dart
final updateResponse = await e2eeClient.request(
  'PATCH',
  '/api/profile',
  body: {'displayName': 'Alice'},
);

final deleteResponse = await e2eeClient.request(
  'DELETE',
  '/api/messages/42',
);
```

### Explicit Handshake

The first protected request performs the handshake automatically. It can also
be started explicitly during application startup:

```dart
await e2eeClient.handshake();

print(e2eeClient.sessionId);
print(e2eeClient.hasActiveSession);
```

Use `await e2eeClient.handshake(force: true)` to replace an active session.

## Base URI and Context Path

Paths beginning with `/` resolve from the host root. If the server uses a
context path, include it in `baseUri` and use relative paths:

```dart
final client = AccloudE2eeClient(
  baseUri: Uri.parse('https://example.com/my-service/'),
  handshakePath: 'e2ee/handshake',
  trustedServerKeys: trustedKeys,
);

final response = await client.get('api/profile');
```

## Session and Error Handling

- Concurrent initial requests share one handshake.
- The session is reused until its signed expiration time.
- A plain, unencrypted `401` or `403` clears the local session. The following
  request performs a new handshake.
- Failed business requests are never replayed automatically, preventing
  duplicate writes.
- `E2eeHandshakeException` reports handshake and trust validation failures.
- `E2eeProtocolException` reports malformed envelopes, invalid IVs, replayed
  responses, and AES-GCM authentication failures.

```dart
try {
  final response = await e2eeClient.get('/api/profile');
  // Handle the HTTP status and decrypted body.
} on E2eeHandshakeException catch (error) {
  print('Handshake failed: $error');
} on E2eeProtocolException catch (error) {
  print('Encrypted response validation failed: $error');
}
```

Call `e2eeClient.clearSession()` after logout or an account switch. Call
`e2eeClient.close()` when the application-level owner is disposed.

## Security Notes

- Use a unique Ed25519 signing key in production. The starter's built-in key
  is for local development only.
- Pin every trusted key by `serverKeyId`. During key rotation, include both the
  old and new public keys until all clients have migrated.
- Use HTTPS in addition to application-layer encryption.
- Do not log session keys, plaintext payloads, private keys, or full encrypted
  envelopes.
- Keep device time synchronized because the server validates millisecond
  timestamps.

## Development

```shell
dart pub get
dart analyze
dart test
```
