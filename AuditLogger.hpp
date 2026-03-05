#pragma once
#include <string>
#include <vector>

#include "SqlAnalyzer.hpp"

// ---------------------------------------------------------------
// AuditRecord
// One record per SQL request - written regardless of allow/deny.
//
// Fields logged and why:
//   timestamp     - when the request arrived (ISO-8601 UTC)
//   user          - who made the request (accountability)
//   role          - user's role at time of request
//   statement_type- SELECT / INSERT / etc. (coarse risk indicator)
//   tables        - which tables were targeted (blast radius)
//   columns       - which columns were projected/affected
//   is_wildcard   - SELECT * is higher risk than explicit columns
//   pii_tags      - PII classifications detected (compliance evidence)
//   allowed       - was the request permitted or denied?
//   deny_reason   - if denied, why (policy traceability)
//   raw_sql       - original statement (forensic completeness)
//   affected_rows - rows changed by DML (impact tracking)
// ---------------------------------------------------------------
struct AuditRecord {
  std::string timestamp;
  std::string user;
  std::string role;
  std::string statement_type;
  std::vector<std::string> tables;
  std::vector<std::string> columns;
  bool is_wildcard = false;
  std::vector<std::string> pii_tags;  // e.g. ["PII.Email", "PII.Phone"]
  bool allowed = false;
  std::string deny_reason;
  std::string raw_sql;
  int affected_rows = 0;
};

// ---------------------------------------------------------------
// AuditLogger
//
// Appends one JSON line per record to audit.jsonl.
// JSONL (newline-delimited JSON) is chosen because:
//   - Append-only - no file locking or rewriting needed
//   - Each line is a valid, self-contained JSON object
//   - Easy to stream into log aggregators (Splunk, ELK, etc.)
// ---------------------------------------------------------------
class AuditLogger {
 public:
  // Opens (or creates) the log file at the given path.
  // Throws on failure to open.
  explicit AuditLogger(const std::string& log_path);

  // Build an AuditRecord from pipeline results and write it.
  void Log(const AuditRecord& record);

  // Convenience builder - constructs record from components.
  // pii_tags are plain strings (e.g. "PII.Email") from Classifier.
  static AuditRecord BuildRecord(const std::string& user,
                                 const std::string& role,
                                 const AnalysisResult& analysis,
                                 const std::vector<std::string>& pii_tags,
                                 bool allowed, const std::string& deny_reason,
                                 int affected_rows = 0);

  // Returns current UTC time as ISO-8601 string (e.g. "2025-03-05T14:32:01Z").
  // Public so callers can stamp records before a BuildRecord is possible.
  static std::string UtcTimestamp();

 private:
  std::string log_path_;

  // Escape a string for safe JSON embedding.
  static std::string JsonEscape(const std::string& s);
};