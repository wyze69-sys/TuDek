class VaultCategory {
  final String id;
  final String name;
  final String khmerName;
  final bool isCritical;

  VaultCategory({
    required this.id,
    required this.name,
    required this.khmerName,
    this.isCritical = false,
  }) {
    if (id.trim().isEmpty || name.trim().isEmpty) {
      throw ArgumentError('Category id and name cannot be empty.');
    }
  }

  static List<VaultCategory> defaultCategories() => [
    VaultCategory(id: 'cat_edu', name: 'Education & CADT', khmerName: 'សាលារៀន និង CADT', isCritical: true),
    VaultCategory(id: 'cat_dev', name: 'Developer & Git', khmerName: 'កូដ និង GitHub', isCritical: true),
    VaultCategory(id: 'cat_fin', name: 'Finance & Banking', khmerName: 'ហិរញ្ញវត្ថុ និងធនាគារ', isCritical: true),
    VaultCategory(id: 'cat_soc', name: 'Social & Messaging', khmerName: 'បណ្ដាញសង្គម'),
    VaultCategory(id: 'cat_per', name: 'Personal & Wi-Fi', khmerName: 'ផ្ទាល់ខ្លួន និង Wi-Fi'),
  ];
}
