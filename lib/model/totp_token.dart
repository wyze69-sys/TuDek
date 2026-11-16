enum TotpAlgorithm {
  sha1,
  sha256,
  sha512;

  String get label => name.toUpperCase();

  static TotpAlgorithm fromString(String raw) {
    switch (raw.trim().toUpperCase().replaceAll('-', '')) {
      case 'SHA1':
        return TotpAlgorithm.sha1;
      case 'SHA256':
        return TotpAlgorithm.sha256;
      case 'SHA512':
        return TotpAlgorithm.sha512;
      default:
        throw const FormatException('Unsupported TOTP algorithm.');
    }
  }
}

String normalizeTotpSecretBase32(String rawSecret) {
  final cleaned = rawSecret.replaceAll(RegExp(r'[\s=-]'), '').toUpperCase();
  if (cleaned.isEmpty || !RegExp(r'^[A-Z2-7]+$').hasMatch(cleaned)) {
    throw const FormatException('Invalid Base32 secret.');
  }
  return cleaned;
}

class TotpToken {
  final String id;
  final String issuer;
  final String accountName;
  final String secretKeyBase32;
  final int periodSeconds;
  final int digits;
  final TotpAlgorithm algorithm;

  TotpToken({
    required this.id,
    required this.issuer,
    required this.accountName,
    required String secretKeyBase32,
    this.periodSeconds = 30,
    this.digits = 6,
    this.algorithm = TotpAlgorithm.sha1,
  }) : secretKeyBase32 = normalizeTotpSecretBase32(secretKeyBase32) {
    if (id.trim().isEmpty || issuer.trim().isEmpty || accountName.trim().isEmpty) {
      throw ArgumentError('Token id, issuer, and accountName cannot be empty.');
    }
    if (periodSeconds != 30 && periodSeconds != 60) {
      throw ArgumentError('TOTP period must be 30 or 60 seconds.');
    }
    if (digits != 6 && digits != 8) {
      throw ArgumentError('TOTP digits must be 6 or 8.');
    }
  }

  String toOtpAuthUri() {
    final encIssuer = Uri.encodeComponent(issuer);
    final encAccount = Uri.encodeComponent(accountName);
    return 'otpauth://totp/$encIssuer:$encAccount'
        '?secret=$secretKeyBase32&issuer=$encIssuer'
        '&algorithm=${algorithm.label}&digits=$digits&period=$periodSeconds';
  }
}
