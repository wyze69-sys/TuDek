enum AuditFindingType {
  passwordReuse,
  weakPassword,
  missingCriticalTotp,
  stalePassword,
  danglingTokenLink,
  sharedTokenViolation,
}

enum AuditSeverity { critical, high, medium, low }

class AuditFinding {
  final AuditFindingType type;
  final AuditSeverity severity;
  final List<String> affectedAccountTitles;
  final String summary;

  AuditFinding({
    required this.type,
    required this.severity,
    required List<String> affectedAccountTitles,
    required this.summary,
  }) : affectedAccountTitles = List.unmodifiable(affectedAccountTitles) {
    if (this.affectedAccountTitles.isEmpty || summary.trim().isEmpty) {
      throw ArgumentError('Audit finding needs at least one account and a summary.');
    }
  }
}

class SecurityAuditReport {
  final DateTime auditDate;
  final int totalAccountsAnalyzed;
  final int? overallHealthScore;
  final List<AuditFinding> findings;

  SecurityAuditReport({
    required this.auditDate,
    required this.totalAccountsAnalyzed,
    required this.overallHealthScore,
    required List<AuditFinding> findings,
  }) : findings = List.unmodifiable(findings) {
    if ((overallHealthScore == null) != (totalAccountsAnalyzed == 0)) {
      throw ArgumentError('Only an empty vault has a null health score.');
    }
  }

  String get ratingLabel {
    final score = overallHealthScore;
    if (score == null) return 'Not Assessed';
    if (score >= 90) return 'Fortress Grade';
    if (score >= 75) return 'Good Standing';
    if (score >= 50) return 'Needs Attention';
    return 'At Risk';
  }
}
