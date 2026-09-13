class E2eeException implements Exception {
  const E2eeException(this.message, [this.cause]);

  final String message;
  final Object? cause;

  @override
  String toString() => 'E2eeException: $message';
}

class E2eeHandshakeException extends E2eeException {
  const E2eeHandshakeException(super.message, [super.cause]);
}

class E2eeProtocolException extends E2eeException {
  const E2eeProtocolException(super.message, [super.cause]);
}
