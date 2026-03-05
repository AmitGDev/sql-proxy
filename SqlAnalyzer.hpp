#pragma once
#include <string>
#include <vector>

// ---------------------------------------------------------------
// StatementType
// ---------------------------------------------------------------
enum class StatementType {
  kSelect,
  kInsert,
  kUpdate,
  kDelete,
  kCreate,
  kAlter,
  kDrop,
  kUnknown
};

std::string ToString(StatementType type);

// ---------------------------------------------------------------
// AnalysisResult
// Holds everything the SqlAnalyzer extracted from one SQL string.
// ---------------------------------------------------------------
struct AnalysisResult {
  StatementType type = StatementType::kUnknown;
  std::vector<std::string> tables;  // all referenced table names (uppercase)
  std::vector<std::string>
      columns;               // projected cols (SELECT) or affected cols (DML)
  bool is_wildcard = false;  // true when SELECT *
  std::string raw_sql;       // original statement (trimmed)
};

// ---------------------------------------------------------------
// SqlAnalyzer
// Regex-based, best-effort SQL analysis.  No full parser - see
// README for documented assumptions and limitations.
// ---------------------------------------------------------------
class SqlAnalyzer {
 public:
  // Main entry point. sql may contain leading/trailing whitespace.
  [[nodiscard]] AnalysisResult Analyze(const std::string& sql) const;

 private:
  [[nodiscard]] StatementType DetectType(const std::string& upper) const;
  [[nodiscard]] std::vector<std::string> ExtractTablesFromSelect(
      const std::string& upper) const;
  [[nodiscard]] std::vector<std::string> ExtractTablesFromDml(
      const std::string& upper, StatementType type) const;
  [[nodiscard]] std::vector<std::string> ExtractTablesFromDdl(
      const std::string& upper, StatementType type) const;
  [[nodiscard]] std::vector<std::string> ExtractSelectColumns(
      const std::string& upper, bool& out_wildcard) const;
  [[nodiscard]] std::vector<std::string> ExtractDmlColumns(
      const std::string& upper, StatementType type) const;

  // Helpers
  [[nodiscard]] static std::string Trim(const std::string& s);
  [[nodiscard]] static std::string ToUpper(std::string s);
  [[nodiscard]] static std::vector<std::string> SplitAndTrim(
      const std::string& s, char delim);
};