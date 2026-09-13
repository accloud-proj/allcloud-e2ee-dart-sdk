import 'dart:convert';

import 'package:accloud_e2ee/accloud_e2ee.dart';

Future<void> main() async {
  final client = AccloudE2eeClient(
    baseUri: Uri.parse('https://api.example.com'),
    trustedServerKeys: const {
      'accloud-e2ee-ed25519-1': 'REPLACE_WITH_SERVER_PUBLIC_KEY',
    },
  );

  try {
    final response = await client.get('/api/profile');
    print(jsonDecode(response.body));
  } finally {
    client.close();
  }
}
