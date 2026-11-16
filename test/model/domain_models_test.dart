import 'package:flutter_test/flutter_test.dart';
import 'package:tudek/model/account_credential.dart';
import 'package:tudek/model/totp_token.dart';
import 'package:tudek/model/vault_category.dart';

void main() {
  final now = DateTime.utc(2026, 3, 1);

  test('rejects invalid AccountCredential and TotpToken inputs', () {
    expect(
      () => AccountCredential(
        id: '',
        title: 'Portal',
        usernameOrEmail: 'student@cadt.edu.kh',
        password: 'secret',
        categoryId: 'cat_edu',
        passwordUpdatedAt: now,
      ),
      throwsArgumentError,
    );
    expect(
      () => TotpToken(
        id: 't1',
        issuer: 'CADT',
        accountName: 'student',
        secretKeyBase32: 'INVALID*01',
      ),
      throwsFormatException,
    );
    expect(
      () => TotpToken(
        id: 't1',
        issuer: 'CADT',
        accountName: 'student',
        secretKeyBase32: 'JBSWY3DPEHPK3PXP',
        periodSeconds: 45,
      ),
      throwsArgumentError,
    );
  });

  test('defaultCategories includes critical CADT and Finance categories', () {
    final categories = VaultCategory.defaultCategories();
    expect(categories.length, 5);
    expect(categories.firstWhere((c) => c.id == 'cat_edu').isCritical, isTrue);
    expect(categories.firstWhere((c) => c.id == 'cat_per').isCritical, isFalse);
  });
}
