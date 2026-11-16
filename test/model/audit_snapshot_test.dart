import 'package:flutter_test/flutter_test.dart';
import 'package:tudek/model/account_credential.dart';
import 'package:tudek/model/security_audit_report.dart';
import 'package:tudek/model/totp_token.dart';
import 'package:tudek/model/vault_category.dart';
import 'package:tudek/model/vault_snapshot.dart';

void main() {
  final now = DateTime.utc(2026, 3, 1);

  test('VaultSnapshot aggregates categories, credentials, and tokens', () {
    final categories = VaultCategory.defaultCategories();
    final token = TotpToken(
      id: 'tok_1',
      issuer: 'CADT',
      accountName: 'student@cadt.edu.kh',
      secretKeyBase32: 'JBSWY3DPEHPK3PXP',
    );
    final cred1 = AccountCredential(
      id: 'c1',
      title: 'CADT Portal',
      usernameOrEmail: 'student@cadt.edu.kh',
      password: 'StrongPassword!2026',
      categoryId: 'cat_edu',
      totpTokenId: token.id,
      passwordUpdatedAt: now,
    );
    final cred2 = AccountCredential(
      id: 'c2',
      title: 'Wi-Fi',
      usernameOrEmail: 'student',
      password: 'CampusWifi#2026',
      categoryId: 'cat_per',
      passwordUpdatedAt: now,
    );

    final snapshot = VaultSnapshot(
      categories: categories,
      credentials: [cred1, cred2],
      tokens: [token],
    );
    expect(snapshot.isEmpty, isFalse);
    expect(snapshot.findCategoryById('cat_edu')?.isCritical, isTrue);
    expect(snapshot.findTokenById('tok_1')?.issuer, 'CADT');
    expect(snapshot.unlinkedCredentials, [cred2]);
  });

  test('SecurityAuditReport enforces empty vs assessed score invariant', () {
    expect(
      () => SecurityAuditReport(
        auditDate: now,
        totalAccountsAnalyzed: 0,
        overallHealthScore: 100,
        findings: const [],
      ),
      throwsArgumentError,
    );
  });
}
