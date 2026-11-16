import 'account_credential.dart';
import 'totp_token.dart';
import 'vault_category.dart';

class VaultSnapshot {
  final List<VaultCategory> categories;
  final List<AccountCredential> credentials;
  final List<TotpToken> tokens;

  const VaultSnapshot({
    required this.categories,
    required this.credentials,
    required this.tokens,
  });

  bool get isEmpty => credentials.isEmpty && tokens.isEmpty;

  VaultCategory? findCategoryById(String id) =>
      categories.where((c) => c.id == id).firstOrNull;

  TotpToken? findTokenById(String id) =>
      tokens.where((t) => t.id == id).firstOrNull;

  List<AccountCredential> get unlinkedCredentials {
    final tokenIds = tokens.map((t) => t.id).toSet();
    return credentials
        .where((c) => c.totpTokenId == null || !tokenIds.contains(c.totpTokenId))
        .toList();
  }
}
