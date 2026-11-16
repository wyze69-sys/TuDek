import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import '../model/totp_token.dart';

class TotpService {
  static const _base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  const TotpService();

  Uint8List decodeBase32(String rawSecret) {
    final cleaned = normalizeTotpSecretBase32(rawSecret);
    final result = Uint8List((cleaned.length * 5) ~/ 8);
    int buffer = 0, bitsLeft = 0, index = 0;

    for (int i = 0; i < cleaned.length; i++) {
      buffer = (buffer << 5) | _base32Alphabet.indexOf(cleaned[i]);
      bitsLeft += 5;
      if (bitsLeft >= 8) {
        bitsLeft -= 8;
        result[index++] = buffer >> bitsLeft;
        buffer &= (1 << bitsLeft) - 1;
      }
    }
    return result;
  }

  String generateHotp(
    Uint8List secretBytes,
    int counter, {
    int digits = 6,
    TotpAlgorithm algorithm = TotpAlgorithm.sha1,
  }) {
    if (secretBytes.isEmpty) throw ArgumentError('Secret bytes cannot be empty.');
    if (counter < 0) throw ArgumentError('Counter cannot be negative.');
    if (digits != 6 && digits != 8) throw ArgumentError('Digits must be 6 or 8.');

    final counterBytes = Uint8List(8);
    int temp = counter;
    for (int i = 7; i >= 0; i--) {
      counterBytes[i] = temp % 256;
      temp ~/= 256;
    }

    final hash = switch (algorithm) {
      TotpAlgorithm.sha1 => sha1,
      TotpAlgorithm.sha256 => sha256,
      TotpAlgorithm.sha512 => sha512,
    };
    final mac = Hmac(hash, secretBytes).convert(counterBytes).bytes;
    final offset = mac.last & 0x0F;
    final binary = ((mac[offset] & 0x7F) << 24) |
        ((mac[offset + 1] & 0xFF) << 16) |
        ((mac[offset + 2] & 0xFF) << 8) |
        (mac[offset + 3] & 0xFF);

    final mod = digits == 8 ? 100000000 : 1000000;
    return (binary % mod).toString().padLeft(digits, '0');
  }

  String generateTotp(TotpToken token, {required DateTime timestamp}) {
    if (timestamp.isBefore(DateTime.fromMillisecondsSinceEpoch(0, isUtc: true))) {
      throw ArgumentError('Timestamp cannot be before Unix epoch.');
    }
    final step = (timestamp.millisecondsSinceEpoch ~/ 1000) ~/ token.periodSeconds;
    return generateHotp(
      decodeBase32(token.secretKeyBase32),
      step,
      digits: token.digits,
      algorithm: token.algorithm,
    );
  }

  int remainingSeconds(int periodSeconds, {required DateTime timestamp}) {
    if (periodSeconds <= 0) throw ArgumentError('periodSeconds must be positive.');
    final seconds = timestamp.millisecondsSinceEpoch ~/ 1000;
    return periodSeconds - (seconds % periodSeconds);
  }

  /// Verifies a code allowing +-1 time step for clock drift.
  bool verifyCode(TotpToken token, String code, {required DateTime timestamp}) {
    final clean = code.replaceAll(RegExp(r'\s+'), '');
    if (clean.length != token.digits) return false;
    final secret = decodeBase32(token.secretKeyBase32);
    final step = (timestamp.millisecondsSinceEpoch ~/ 1000) ~/ token.periodSeconds;

    for (final offset in [-1, 0, 1]) {
      if (step + offset < 0) continue;
      final expected = generateHotp(
        secret,
        step + offset,
        digits: token.digits,
        algorithm: token.algorithm,
      );
      if (clean == expected) return true;
    }
    return false;
  }

  TotpToken parseOtpAuthUri(String rawUri, {String? id}) {
    final uri = Uri.tryParse(rawUri.trim());
    if (uri == null || uri.scheme.toLowerCase() != 'otpauth' || uri.host.toLowerCase() != 'totp') {
      throw const FormatException('Expected a valid otpauth://totp/ URI.');
    }
    final secret = uri.queryParameters['secret'];
    if (secret == null || secret.trim().isEmpty) {
      throw const FormatException('Missing secret parameter.');
    }

    final label = uri.pathSegments.isEmpty ? '' : uri.pathSegments.single;
    final sep = label.indexOf(':');
    final labelIssuer = sep < 0 ? '' : label.substring(0, sep).trim();
    final account = (sep < 0 ? label : label.substring(sep + 1)).trim();
    final issuer = (uri.queryParameters['issuer'] ?? '').trim();

    return TotpToken(
      id: id ?? 'totp_${DateTime.now().microsecondsSinceEpoch}',
      issuer: issuer.isNotEmpty ? issuer : (labelIssuer.isNotEmpty ? labelIssuer : 'Unknown'),
      accountName: account.isNotEmpty ? account : 'account',
      secretKeyBase32: secret,
      algorithm: TotpAlgorithm.fromString(uri.queryParameters['algorithm'] ?? 'SHA1'),
      digits: int.parse(uri.queryParameters['digits'] ?? '6'),
      periodSeconds: int.parse(uri.queryParameters['period'] ?? '30'),
    );
  }
}
