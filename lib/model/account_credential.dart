class AccountCredential {
  final String id;
  final String title;
  final String usernameOrEmail;
  final String password;
  final String categoryId;
  final String? totpTokenId;
  final DateTime passwordUpdatedAt;

  AccountCredential({
    required this.id,
    required this.title,
    required this.usernameOrEmail,
    required this.password,
    required this.categoryId,
    this.totpTokenId,
    required this.passwordUpdatedAt,
  }) {
    if (id.trim().isEmpty || title.trim().isEmpty || usernameOrEmail.trim().isEmpty) {
      throw ArgumentError('Credential id, title, and username cannot be empty.');
    }
    if (password.isEmpty || categoryId.trim().isEmpty) {
      throw ArgumentError('Password and categoryId cannot be empty.');
    }
    if (totpTokenId != null && totpTokenId!.trim().isEmpty) {
      throw ArgumentError('Linked totpTokenId cannot be empty.');
    }
  }
}
