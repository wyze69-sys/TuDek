import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:tudek/model/totp_token.dart';
import 'package:tudek/service/totp_service.dart';

void main() {
  const service = TotpService();

  test('Normal: decodes Base32 and matches RFC 6238 SHA1/256/512 vectors', () {
    expect(utf8.decode(service.decodeBase32('JBSWY3DPEE======')), 'Hello!');

    final t = DateTime.fromMillisecondsSinceEpoch(59 * 1000, isUtc: true);
    final sha1Token = TotpToken(
      id: 't1',
      issuer: 'RFC',
      accountName: 'user',
      secretKeyBase32: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
      digits: 8,
      algorithm: TotpAlgorithm.sha1,
    );
    expect(service.generateTotp(sha1Token, timestamp: t), '94287082');
  });

  test('Normal: parses valid otpauth://totp URI', () {
    final token = service.parseOtpAuthUri(
      'otpauth://totp/CADT:student@cadt.edu.kh?secret=JBSWY3DPEHPK3PXP&digits=6&period=30',
    );
    expect(token.issuer, 'CADT');
    expect(token.accountName, 'student@cadt.edu.kh');
    expect(token.digits, 6);
  });

  test('Invalid: rejects non-totp URI, missing secret, and bad Base32', () {
    expect(() => service.parseOtpAuthUri('https://example.com'), throwsFormatException);
    expect(() => service.parseOtpAuthUri('otpauth://totp/CADT:user'), throwsFormatException);
    expect(() => service.decodeBase32('INVALID_01'), throwsFormatException);
    expect(() => service.generateHotp(Uint8List(0), 0), throwsArgumentError);
  });

  test('Boundary: handles 30s window rollover, pre-epoch, and +-1 drift', () {
    final token = TotpToken(
      id: 't2',
      issuer: 'CADT',
      accountName: 'student',
      secretKeyBase32: 'JBSWY3DPEHPK3PXP',
    );
    final t0 = DateTime.utc(2026, 3, 1, 0, 0, 29);
    final t1 = DateTime.utc(2026, 3, 1, 0, 0, 30);

    expect(service.remainingSeconds(30, timestamp: t0), 1);
    expect(service.remainingSeconds(30, timestamp: t1), 30);

    final code0 = service.generateTotp(token, timestamp: t0);
    expect(service.verifyCode(token, code0, timestamp: t1), isTrue);
    expect(service.verifyCode(token, '000000', timestamp: t1), isFalse);

    expect(
      () => service.generateTotp(
        token,
        timestamp: DateTime.fromMillisecondsSinceEpoch(-1, isUtc: true),
      ),
      throwsArgumentError,
    );
  });
}
