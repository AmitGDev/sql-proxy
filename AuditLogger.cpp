#include "AuditLogger.hpp"

#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

// ---------------------------------------------------------------
// AuditLogger
// ---------------------------------------------------------------
AuditLogger::AuditLogger(const std::string& log_path) : log_path_(log_path) {
  // Verify we can open the file for appending on construction.
  std::ofstream test(log_path_, std::ios::app);
  if (!test.is_open())
    throw std::runtime_error("AuditLogger: cannot open log file: " + log_path_);
}

// ---------------------------------------------------------------
// BuildRecord
// ---------------------------------------------------------------
AuditRecord AuditLogger::BuildRecord(
    const std::string& user, const std::string& role,
    const AnalysisResult& analysis, const std::vector<std::string>& pii_tags,
    bool allowed, const std::string& deny_reason, int affected_rows) {
  AuditRecord rec;
  rec.timestamp = UtcTimestamp();
  rec.user = user;
  rec.role = role;
  rec.statement_type = ToString(analysis.type);
  rec.tables = analysis.tables;
  rec.columns = analysis.columns;
  rec.is_wildcard = analysis.is_wildcard;
  rec.allowed = allowed;
  rec.deny_reason = deny_reason;
  rec.raw_sql = analysis.raw_sql;
  rec.affected_rows = affected_rows;
  rec.pii_tags = pii_tags;  // already strings - no conversion needed
  return rec;
}

// ---------------------------------------------------------------
// Log
// Serialises the record as a single JSON line and appends it.
// ---------------------------------------------------------------
void AuditLogger::Log(const AuditRecord& rec) {
  std::ostringstream json;

  // Helper lambdas for inline JSON array serialisation
  auto json_str_array = [&](const std::vector<std::string>& v) -> std::string {
    std::ostringstream os;
    os << "[";
    for (size_t i = 0; i < v.size(); ++i)
      os << (i ? "," : "") << "\"" << JsonEscape(v[i]) << "\"";
    os << "]";
    return os.str();
  };

  json << "{"
       << "\"timestamp\":" << "\"" << JsonEscape(rec.timestamp) << "\","
       << "\"user\":" << "\"" << JsonEscape(rec.user) << "\","
       << "\"role\":" << "\"" << JsonEscape(rec.role) << "\","
       << "\"statement_type\":" << "\"" << JsonEscape(rec.statement_type)
       << "\","
       << "\"tables\":" << json_str_array(rec.tables) << ","
       << "\"columns\":" << json_str_array(rec.columns) << ","
       << "\"is_wildcard\":" << (rec.is_wildcard ? "true" : "false") << ","
       << "\"pii_tags\":" << json_str_array(rec.pii_tags) << ","
       << "\"allowed\":" << (rec.allowed ? "true" : "false") << ","
       << "\"deny_reason\":" << "\"" << JsonEscape(rec.deny_reason) << "\","
       << "\"affected_rows\":" << rec.affected_rows << ","
       << "\"raw_sql\":" << "\"" << JsonEscape(rec.raw_sql) << "\""
       << "}";

  std::ofstream file(log_path_, std::ios::app);
  if (!file.is_open())
    throw std::runtime_error("AuditLogger: cannot write to log file: " +
                             log_path_);

  file << json.str() << "\n";
}

// ---------------------------------------------------------------
// JsonEscape
// Escapes characters that would break JSON string values.
// ---------------------------------------------------------------
std::string AuditLogger::JsonEscape(const std::string& s) {
  std::ostringstream out;
  for (const char c : s) {
    switch (c) {
      case '"':
        out << "\\\"";
        break;
      case '\\':
        out << "\\\\";
        break;
      case '\n':
        out << "\\n";
        break;
      case '\r':
        out << "\\r";
        break;
      case '\t':
        out << "\\t";
        break;
      default:
        out << c;
        break;
    }
  }
  return out.str();
}

// ---------------------------------------------------------------
// UtcTimestamp
// Returns the current UTC time as an ISO-8601 string.
// e.g. "2025-03-05T14:32:01Z"
// ---------------------------------------------------------------
std::string AuditLogger::UtcTimestamp() {
  const auto now = std::chrono::system_clock::now();
  const std::time_t t = std::chrono::system_clock::to_time_t(now);
  std::tm utc{};
#if defined(_WIN32)
  gmtime_s(&utc, &t);
#else
  gmtime_r(&t, &utc);
#endif
  std::ostringstream ss;
  ss << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
  return ss.str();
}