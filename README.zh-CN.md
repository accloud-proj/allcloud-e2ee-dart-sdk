# Accloud E2EE Dart SDK

[English](README.md) | [简体中文](README.zh-CN.md)

用于和 `accloud-e2ee-spring-boot-starter` 所保护接口通信的 Dart/Flutter
客户端 SDK。

## 功能特性

- X25519 临时密钥协商
- HKDF-SHA256 会话密钥派生
- AES-256-GCM 请求和响应加密
- Ed25519 服务端握手签名验证
- 客户端到服务端、服务端到客户端使用独立密钥和 IV
- 请求和响应序列号防重放
- 支持 Android、iOS、Web、桌面端和 Dart VM

当前协议版本为 `1`，使用的密码套件为
`X25519+HKDF-SHA256+AES-256-GCM+Ed25519`。

## 安装

发布到 pub.dev 前，可以使用 Git 依赖：

```yaml
dependencies:
  accloud_e2ee:
    git:
      url: https://github.com/accloud-proj/allcloud-e2ee-dart-sdk.git
      ref: main
```

安装依赖：

```shell
flutter pub get
```

纯 Dart 项目请使用 `dart pub get`。

## 服务端要求

Spring Boot 应用必须暴露 E2EE 握手端点，并将该路径排除在加密过滤器之外：

```yaml
accloud.e2ee.enabled: true
accloud.e2ee.protected-path-prefixes: [/api/**]
accloud.e2ee.bypass-paths: [/e2ee/handshake]
accloud.e2ee.sign-key-id: accloud-e2ee-ed25519-1
accloud.e2ee.sign-private-key: ${E2EE_SIGN_PRIVATE_KEY}
accloud.e2ee.sign-public-key: ${E2EE_SIGN_PUBLIC_KEY}
```

握手端点需要调用 `E2eeHandshakeService`：

```java
@PostMapping("/e2ee/handshake")
public HandshakeResponse handshake(@RequestBody HandshakeRequest request) {
    return handshakeService.handshake(request);
}
```

服务端返回的 `serverKeyId` 必须与客户端 `trustedServerKeys` 中的 key 一致。

## 快速开始

创建一个客户端并在接口请求之间复用。不要为每次请求创建新客户端，因为客户端负责
保存 E2EE 会话和序列号。

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
    throw StateError('请求失败：${response.statusCode}');
  }
  return jsonDecode(response.body) as Map<String, dynamic>;
}
```

可信 Ed25519 公钥支持 X.509/PKIX PEM 字符串，或其标准 Base64 编码的 DER
内容。请通过可信渠道分发并内置该公钥，不能从握手接口动态下载信任公钥。

## 发送请求

### GET 请求

无 body 请求会自动通过 `X-E2EE-*` headers 发送 session ID、序列号和时间戳。
query 参数不参与 AAD 计算，与 Spring Boot 服务端实现保持一致。

```dart
final response = await e2eeClient.get(
  '/api/messages',
  queryParameters: {'page': 1, 'size': 20},
  headers: {'authorization': 'Bearer $accessToken'},
);

final data = jsonDecode(response.body);
```

### JSON POST 请求

Map 和其他可 JSON 编码的对象会先编码成 UTF-8 JSON，再进行加密：

```dart
final response = await e2eeClient.post(
  '/api/messages',
  body: {
    'recipientId': 'user-1001',
    'text': '你好',
  },
  headers: {'authorization': 'Bearer $accessToken'},
);
```

`body` 支持可进行 JSON 编码的对象、按 UTF-8 编码的 `String`、直接作为待加密
明文字节的 `List<int>`，以及表示空 body 的 `null`。

### 其他 HTTP 方法

PUT、PATCH、DELETE 或其他方法可以使用 `request()`：

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

### 主动握手

第一次受保护请求会自动握手。也可以在应用启动等场景中主动执行：

```dart
await e2eeClient.handshake();

print(e2eeClient.sessionId);
print(e2eeClient.hasActiveSession);
```

使用 `await e2eeClient.handshake(force: true)` 可以替换当前有效会话。

## Base URI 与 Context Path

以 `/` 开头的路径会从主机根路径解析。如果服务端配置了 context path，请将它包含
在 `baseUri` 中，并使用相对路径：

```dart
final client = AccloudE2eeClient(
  baseUri: Uri.parse('https://example.com/my-service/'),
  handshakePath: 'e2ee/handshake',
  trustedServerKeys: trustedKeys,
);

final response = await client.get('api/profile');
```

## 会话与异常处理

- 并发发起的首批请求共享同一个握手。
- 会话会一直复用到签名响应声明的过期时间。
- 服务端返回未加密的 `401` 或 `403` 时，本地 session 会被清除，下一次请求会
  重新握手。
- SDK 不会自动重放失败的业务请求，以避免重复写入。
- `E2eeHandshakeException` 表示握手或信任验证失败。
- `E2eeProtocolException` 表示信封格式、IV、防重放或 AES-GCM 认证失败。

```dart
try {
  final response = await e2eeClient.get('/api/profile');
  // 处理 HTTP 状态码和已解密的 body。
} on E2eeHandshakeException catch (error) {
  print('握手失败：$error');
} on E2eeProtocolException catch (error) {
  print('加密响应校验失败：$error');
}
```

用户退出登录或切换账号时调用 `e2eeClient.clearSession()`。持有客户端的应用级对象
销毁时调用 `e2eeClient.close()`。

## 安全建议

- 生产环境必须使用独立的 Ed25519 签名密钥，starter 内置密钥只能用于本地开发。
- 每个可信公钥都要通过 `serverKeyId` 固定。轮换密钥时，可以暂时同时内置新旧公钥，
  直到所有客户端完成升级。
- 应用层加密之外仍然必须使用 HTTPS。
- 不要记录 session key、明文、私钥或完整加密信封。
- 保持设备时间同步，服务端会校验毫秒时间戳。

## 开发

```shell
dart pub get
dart analyze
dart test
```
