import 'dart:math';
import 'package:flutter_test/flutter_test.dart';
import 'package:tudek/model/account_credential.dart';
import 'package:tudek/model/security_audit_report.dart';
import 'package:tudek/model/totp_token.dart';
import 'package:tudek/model/vault_category.dart';
import 'package:tudek/model/vault_snapshot.dart';
import 'package:tudek/service/vault_security_service.dart';

void main() {
  const service = VaultSecurityService();
  final now = DateTime.utc(2026, 10, 1);
  final categories = VaultCategory.defaultCategories();

  test('Normal: generates valid password and scores strong vs weak', () {
    final pw = service.generatePassword(length: 16, random: Random(42));
    expect(pw.length, 16);
    expect(service.estimatePasswordStrength(pw).level, PasswordStrengthLevel.strong);
    expect(service.estimatePasswordStrength('password').level, PasswordStrengthLevel.weak);
  });

  test('Invalid: rejects out-of-range password length', () {
    expect(() => service.generatePassword(length: 7), throwsArgumentError);
    expect(() => service.generatePassword(length: 65), throwsArgumentError);
  });

  test('Normal: healthy vault scores 100 with zero findings', () {
    final token = TotpToken(
      id: 'tok_1',
      issuer: 'CADT',
      accountName: 'student',
      secretKeyBase32: 'JBSWY3DPEHPK3PXP',
    );
    final cred = AccountCredential(
      id: 'c1',
      title: 'CADT Portal',
      usernameOrEmail: 'student@cadt.edu.kh',
      password: 'V@ultGrade#2026Secure!',
      categoryId: 'cat_edu',
      totpTokenId: token.id,
      passwordUpdatedAt: now,
    );

    final report = service.auditSnapshot(
      VaultSnapshot(categories: categories, credentials: [cred], tokens: [token]),
      now: now,
    );
    expect(report.overallHealthScore, 100);
    expect(report.findings, isEmpty);
    expect(report.ratingLabel, 'Fortress Grade');
  });

  test('Invalid: detects reused, weak, missing 2FA, dangling link, and shared token', () {
    final token = TotpToken(
      id: 'tok_1',
      issuer: 'GitHub',
      accountName: 'student',
      secretKeyBase32: 'JBSWY3DPEHPK3PXP',
    );
    final creds = [
      AccountCredential(
        id: 'c1',
        title: 'Account A',
        usernameOrEmail: 'a',
        password: 'password',
        categoryId: 'cat_edu',
        totpTokenId: token.id,
        passwordUpdatedAt: now,
      ),
      AccountCredential(
        id: 'c2',
        title: 'Account B',
        usernameOrEmail: 'b',
        password: 'password',
        categoryId: 'cat_fin',
        totpTokenId: 'missing_tok',
        passwordUpdatedAt: now,
      ),
      AccountCredential(
        id: 'c3',
        title: 'Account C',
        usernameOrEmail: 'c',
        password: 'Unique#Strong99!',
        categoryId: 'cat_dev',
        totpTokenId: token.id,
        passwordUpdatedAt: now,
      ),
    ];

    final report = service.auditVault(
      credentials: creds,
      tokens: [token],
      categories: categories,
      now: now,
    );
    final types = report.findings.map((f) => f.type).toSet();
    expect(types, containsAll([
      AuditFindingType.passwordReuse,
      AuditFindingType.weakPassword,
      AuditFindingType.danglingTokenLink,
      AuditFindingType.missingCriticalTotp,
      AuditFindingType.sharedTokenViolation,
    ]));
  });

  test('Boundary: empty vault returns null score and 180 vs 181 days stale check', () {
    final emptyReport = service.auditVault(
      credentials: const [],
      tokens: const [],
      categories: categories,
      now: now,
    );
    expect(emptyReport.overallHealthScore, isNull);
    expect(emptyReport.ratingLabel, 'Not Assessed');

    final token = TotpToken(
      id: 'tok_1',
      issuer: 'CADT',
      accountName: 'student',
      secretKeyBase32: 'JBSWY3DPEHPK3PXP',
    );
    final exact180 = AccountCredential(
      id: 'c1',
      title: 'Exact 180',
      usernameOrEmail: 'u',
      password: 'Unique#Strong99!',
      categoryId: 'cat_edu',
      totpTokenId: token.id,
      passwordUpdatedAt: now.subtract(const Duration(days: 180)),
    );
    final over180 = AccountCredential(
      id: 'c2',
      title: 'Over 180',
      usernameOrEmail: 'u2',
      password: 'Another#Strong88!',
      categoryId: 'cat_per',
      passwordUpdatedAt: now.subtract(const Duration(days: 181)),
    );

    final report = service.auditVault(
      credentials: [exact180, over180],
      tokens: [token],
      categories: categories,
      now: now,
    );
    expect(report.findings.length, 1);
    expect(report.findings.single.type, AuditFindingType.stalePassword);
    expect(report.findings.single.affectedAccountTitles, ['Over 180']);
  });
}
