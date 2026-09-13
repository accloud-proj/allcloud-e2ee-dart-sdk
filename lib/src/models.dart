class HandshakeRequest {
  const HandshakeRequest({
    required this.version,
    required this.clientEphemeralPubKey,
    required this.clientNonce,
    required this.ts,
    required this.cipherSuites,
  });

  final String version;
  final String clientEphemeralPubKey;
  final String clientNonce;
  final int ts;
  final List<String> cipherSuites;

  Map<String, Object> toJson() => {
        'version': version,
        'clientEphemeralPubKey': clientEphemeralPubKey,
        'clientNonce': clientNonce,
        'ts': ts,
        'cipherSuites': cipherSuites,
      };
}

class HandshakeResponse {
  const HandshakeResponse({
    required this.version,
    required this.sessionId,
    required this.serverEphemeralPubKey,
    required this.serverNonce,
    required this.ts,
    required this.expireAt,
    required this.suite,
    required this.serverKeyId,
    required this.signature,
  });

  factory HandshakeResponse.fromJson(Map<String, Object?> json) =>
      HandshakeResponse(
        version: json['version'] as String,
        sessionId: json['sessionId'] as String,
        serverEphemeralPubKey: json['serverEphemeralPubKey'] as String,
        serverNonce: json['serverNonce'] as String,
        ts: (json['ts'] as num).toInt(),
        expireAt: (json['expireAt'] as num).toInt(),
        suite: json['suite'] as String,
        serverKeyId: json['serverKeyId'] as String,
        signature: json['signature'] as String,
      );

  final String version;
  final String sessionId;
  final String serverEphemeralPubKey;
  final String serverNonce;
  final int ts;
  final int expireAt;
  final String suite;
  final String serverKeyId;
  final String signature;
}

class EncryptedPayload {
  const EncryptedPayload({
    required this.sessionId,
    required this.seq,
    required this.ts,
    required this.iv,
    required this.ciphertext,
  });

  factory EncryptedPayload.fromJson(Map<String, Object?> json) =>
      EncryptedPayload(
        sessionId: json['sessionId'] as String,
        seq: (json['seq'] as num).toInt(),
        ts: (json['ts'] as num).toInt(),
        iv: json['iv'] as String,
        ciphertext: json['ciphertext'] as String,
      );

  final String sessionId;
  final int seq;
  final int ts;
  final String iv;
  final String ciphertext;

  Map<String, Object> toJson() => {
        'sessionId': sessionId,
        'seq': seq,
        'ts': ts,
        'iv': iv,
        'ciphertext': ciphertext,
      };
}
