import 'dart:math';

import '../model/account_credential.dart';
import '../model/security_audit_report.dart';
import '../model/totp_token.dart';
import '../model/vault_category.dart';
import '../model/vault_snapshot.dart';

enum PasswordStrengthLevel { weak, fair, good, strong }

class PasswordStrengthResult {
  final int score; // 0..100
  final PasswordStrengthLevel level;

  const PasswordStrengthResult(this.score, this.level);
}

class VaultSecurityService {
  static const int staleDays = 180;
  static const _weakWords = {'password', '123456', '12345678', 'qwerty', 'admin', 'cadt', 'student'};

  const VaultSecurityService();

  String generatePassword({int length = 16, bool includeSymbols = true, Random? random}) {
    if (length < 8 || length > 64) {
      throw ArgumentError('Password length must be between 8 and 64.');
    }
    final rng = random ?? Random.secure();
    final pools = [
      'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
      'abcdefghijklmnopqrstuvwxyz',
      '0123456789',
      if (includeSymbols) '!@#\$%^&*()-_=+',
    ];
    final allChars = pools.join();
    final chars = [for (final p in pools) p[rng.nextInt(p.length)]];
    while (chars.length < length) {
      chars.add(allChars[rng.nextInt(allChars.length)]);
    }
    chars.shuffle(rng);
    return chars.join();
  }

  PasswordStrengthResult estimatePasswordStrength(String password) {
    if (password.isEmpty) return const PasswordStrengthResult(0, PasswordStrengthLevel.weak);

    final lower = password.toLowerCase();
    if (_weakWords.contains(lower)) {
      return const PasswordStrengthResult(10, PasswordStrengthLevel.weak);
    }

    int score = (password.length * 4).clamp(0, 50);
    if (RegExp(r'[a-z]').hasMatch(password)) score += 10;
    if (RegExp(r'[A-Z]').hasMatch(password)) score += 15;
    if (RegExp(r'[0-9]').hasMatch(password)) score += 10;
    if (RegExp(r'[^a-zA-Z0-9]').hasMatch(password)) score += 15;
    if (password.length < 8) score = score.clamp(0, 30);
    if (_weakWords.any(lower.contains)) score = (score - 30).clamp(0, 100);

    final level = score < 40
        ? PasswordStrengthLevel.weak
        : score < 65
            ? PasswordStrengthLevel.fair
            : score < 85
                ? PasswordStrengthLevel.good
                : PasswordStrengthLevel.strong;

    return PasswordStrengthResult(score.clamp(0, 100), level);
  }

  SecurityAuditReport auditSnapshot(VaultSnapshot snapshot, {required DateTime now}) =>
      auditVault(
        credentials: snapshot.credentials,
        tokens: snapshot.tokens,
        categories: snapshot.categories,
        now: now,
      );

  SecurityAuditReport auditVault({
    required List<AccountCredential> credentials,
    required List<TotpToken> tokens,
    required List<VaultCategory> categories,
    required DateTime now,
  }) {
    if (credentials.isEmpty) {
      return SecurityAuditReport(
        auditDate: now,
        totalAccountsAnalyzed: 0,
        overallHealthScore: null,
        findings: const [],
      );
    }

    final findings = <AuditFinding>[];
    final tokenIds = tokens.map((t) => t.id).toSet();
    final categoryMap = {for (final c in categories) c.id: c};
    int penalty = 0;

    // 1. Reused passwords
    final byPassword = <String, List<AccountCredential>>{};
    for (final c in credentials) {
      byPassword.putIfAbsent(c.password, () => []).add(c);
    }
    for (final group in byPassword.values.where((g) => g.length >= 2)) {
      penalty += group.length * 16;
      findings.add(AuditFinding(
        type: AuditFindingType.passwordReuse,
        severity: AuditSeverity.critical,
        affectedAccountTitles: group.map((c) => c.title).toList(),
        summary: '${group.length} accounts share the same password.',
      ));
    }

    // 2. Per-account checks: weak password, dangling/missing 2FA, stale password
    final tokenUsage = <String, List<AccountCredential>>{};
    for (final c in credentials) {
      if (estimatePasswordStrength(c.password).score < 50) {
        penalty += 15;
        findings.add(AuditFinding(
          type: AuditFindingType.weakPassword,
          severity: AuditSeverity.high,
          affectedAccountTitles: [c.title],
          summary: '${c.title} has a weak password.',
        ));
      }

      final hasToken = c.totpTokenId != null && tokenIds.contains(c.totpTokenId);
      if (hasToken) {
        tokenUsage.putIfAbsent(c.totpTokenId!, () => []).add(c);
      } else {
        if (c.totpTokenId != null) {
          penalty += 14;
          findings.add(AuditFinding(
            type: AuditFindingType.danglingTokenLink,
            severity: AuditSeverity.high,
            affectedAccountTitles: [c.title],
            summary: '${c.title} links to a missing TOTP token.',
          ));
        }
        if (categoryMap[c.categoryId]?.isCritical ?? false) {
          penalty += 8;
          findings.add(AuditFinding(
            type: AuditFindingType.missingCriticalTotp,
            severity: AuditSeverity.medium,
            affectedAccountTitles: [c.title],
            summary: '${c.title} is in a critical category without 2FA.',
          ));
        }
      }

      if (now.difference(c.passwordUpdatedAt) > const Duration(days: staleDays)) {
        penalty += 4;
        findings.add(AuditFinding(
          type: AuditFindingType.stalePassword,
          severity: AuditSeverity.low,
          affectedAccountTitles: [c.title],
          summary: '${c.title} password is older than $staleDays days.',
        ));
      }
    }

    // 3. Shared TOTP token check
    for (final group in tokenUsage.values.where((g) => g.length >= 2)) {
      penalty += group.length * 8;
      findings.add(AuditFinding(
        type: AuditFindingType.sharedTokenViolation,
        severity: AuditSeverity.medium,
        affectedAccountTitles: group.map((c) => c.title).toList(),
        summary: 'Multiple accounts share the same TOTP token.',
      ));
    }

    return SecurityAuditReport(
      auditDate: now,
      totalAccountsAnalyzed: credentials.length,
      overallHealthScore: (100 - penalty).clamp(0, 100),
      findings: findings,
    );
  }
}
