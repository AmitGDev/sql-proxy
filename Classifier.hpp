#pragma once
#include <string>
#include <vector>

// ---------------------------------------------------------------
// ClassificationResult
//
// Tags are plain strings (e.g. "PII.Email", "PII.Phone", "PII.SSN")
// loaded from classifier.json at runtime - not a hardcoded enum.
// This means new PII categories require only a config change,
// no recompile.
// ---------------------------------------------------------------
struct ClassificationResult {
  std::vector<std::string> tags;  // deduplicated list of matched tags
  bool HasAny() const { return !tags.empty(); }
};

// ---------------------------------------------------------------
// Classifier
//
// Classifies sensitive data exposure based on column names.
//
// PII patterns are loaded from classifier.json at startup via
// LoadFromFile(). Falls back to built-in defaults via
// LoadDefaults() if no config file is available.
//
// Table schema (for wildcard expansion) is loaded from
// schema.json via LoadSchemaFromFile().
//
// Operates in two modes:
//   1. Explicit - checks a provided list of column names
//   2. Wildcard - expands SELECT * via the registered schema
//      for the referenced table, then checks all columns
// ---------------------------------------------------------------
class Classifier {
 public:
  // Load PII patterns from a JSON config file.
  // See classifier.json for the expected format.
  // Throws std::runtime_error if the file cannot be opened.
  void LoadFromFile(const std::string& path);

  // Load hardcoded built-in defaults (email, phone).
  // Used as fallback when no config file is present.
  void LoadDefaults();

  // Load table schema from config/schema.json for wildcard expansion.
  // Throws std::runtime_error if the file cannot be opened.
  void LoadSchemaFromFile(const std::string& path);

  // Load hardcoded built-in schema (four demo tables).
  // Used as fallback when schema.json is missing.
  void LoadSchemaDefaults();

  // Classify based on column names extracted by SqlAnalyzer.
  // Pass is_wildcard=true + table_name to trigger schema lookup.
  ClassificationResult Classify(const std::vector<std::string>& columns,
                                bool is_wildcard = false,
                                const std::string& table_name = "") const;

  // Register which columns a table contains (for wildcard expansion).
  // Call once at startup for each table in the schema.
  void RegisterTableColumns(const std::string& table_name,
                            const std::vector<std::string>& columns);

 private:
  // One loaded rule: a set of column name patterns → one tag string.
  struct PiiRule {
    std::vector<std::string> patterns;  // uppercase column name patterns
    std::string tag;                    // e.g. "PII.Email"
  };

  std::vector<PiiRule> rules_;  // loaded from config or defaults

  // table_name (upper) → list of column names (upper)
  std::vector<std::pair<std::string, std::vector<std::string>>> schema_;

  // Returns all matching tags for a single uppercase column name.
  std::vector<std::string> ClassifyColumn(const std::string& upper_col) const;

  // Fetch registered columns for a table (empty if unknown).
  std::vector<std::string> ColumnsForTable(
      const std::string& upper_table) const;
};