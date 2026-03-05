#include "SqlAnalyzer.hpp"

#include <algorithm>
#include <cctype>
#include <ranges>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

namespace {

// Returns only the first word - strips bare aliases like "customers c"
// so the table name is clean before it enters the policy engine.
std::string FirstWord(const std::string& s) {
  auto sp = s.find(' ');
  return (sp == std::string::npos) ? s : s.substr(0, sp);
}

}  // namespace

// ---------------------------------------------------------------
// ToString
// Converts StatementType to the SQL keyword string used in audit
// records and console output. kUnknown covers any statement the
// analyzer could not classify.
// ---------------------------------------------------------------
std::string ToString(StatementType type) {
  switch (type) {
    case StatementType::kSelect:
      return "SELECT";
    case StatementType::kInsert:
      return "INSERT";
    case StatementType::kUpdate:
      return "UPDATE";
    case StatementType::kDelete:
      return "DELETE";
    case StatementType::kCreate:
      return "CREATE";
    case StatementType::kAlter:
      return "ALTER";
    case StatementType::kDrop:
      return "DROP";
    default:
      return "UNKNOWN";
  }
}

// ---------------------------------------------------------------
// Analyze
// Entry point for the entire analysis pipeline. The result is
// consumed by PolicyEngine (tables), Classifier (columns), and
// AuditLogger (everything). All downstream components trust this
// output - unknown/unparseable statements surface as kUnknown
// with empty tables/columns rather than throwing.
// ---------------------------------------------------------------
AnalysisResult SqlAnalyzer::Analyze(const std::string& sql) const {
  AnalysisResult result;
  result.raw_sql = Trim(sql);

  // Uppercase once here - all sub-methods receive the uppercased
  // copy so regex patterns can be written without case flags.
  const std::string upper = ToUpper(result.raw_sql);
  result.type = DetectType(upper);

  // Route extraction based on statement type.
  // Each branch populates result.tables and/or result.columns - the two
  // fields consumed by the downstream pipeline (PolicyEngine, Classifier,
  // AuditLogger). The amount extracted differs per category:
  switch (result.type) {
    case StatementType::kSelect:
      // SELECT needs both the source tables and the projected columns:
      //   - tables  → policy engine decides if the user can read from this table
      //   - columns → Classifier checks if the projection exposes PII columns
      //               (e.g. SELECT email, phone) and sets is_wildcard=true
      //               when SELECT * is used so the Classifier can expand it
      //               against the registered schema rather than leaving it
      //               blank.
      result.tables = ExtractTablesFromSelect(upper);
      result.columns = ExtractSelectColumns(upper, result.is_wildcard);
      break;
    case StatementType::kInsert:
    case StatementType::kUpdate:
    case StatementType::kDelete:
      // DML needs both the target table and the affected columns:
      //   - tables  → policy engine decides if the user can write to this table
      //   - columns → Classifier checks if the write touches PII columns
      //               (e.g. INSERT including email, UPDATE setting phone)
      //               and AuditLogger records exactly which columns were
      //               written.
      result.tables = ExtractTablesFromDml(upper, result.type);
      result.columns = ExtractDmlColumns(upper, result.type);
      break;
    case StatementType::kCreate:
    case StatementType::kAlter:
    case StatementType::kDrop:
      // DDL operates on the table structure itself, not on individual columns.
      // Only the target table is extracted - enough for the policy engine to
      // decide if the user is allowed to run DDL on that table at all.
      result.tables = ExtractTablesFromDdl(upper, result.type);
      break;
    default:
      // UNKNOWN - statement could not be classified. Tables and columns remain
      // empty. The pipeline continues and the audit log records the raw SQL,
      // letting the policy engine apply its default-deny rule.
      break;
  }

  return result;
}

// ---------------------------------------------------------------
// DetectType
// Identifies the statement type from its first keyword. This
// drives the entire downstream branch - getting it wrong means
// wrong table extraction, wrong policy evaluation, and wrong
// audit classification.
// ---------------------------------------------------------------
StatementType SqlAnalyzer::DetectType(const std::string& upper) const {
  const std::string s = Trim(upper);

  if (s.starts_with("SELECT")) {
    return StatementType::kSelect;
  }
  if (s.starts_with("INSERT")) {
    return StatementType::kInsert;
  }
  if (s.starts_with("UPDATE")) {
    return StatementType::kUpdate;
  }
  if (s.starts_with("DELETE")) {
    return StatementType::kDelete;
  }
  if (s.starts_with("CREATE")) {
    return StatementType::kCreate;
  }
  if (s.starts_with("ALTER")) {
    return StatementType::kAlter;
  }
  if (s.starts_with("DROP")) {
    return StatementType::kDrop;
  }

  return StatementType::kUnknown;
}

// ---------------------------------------------------------------
// ExtractTablesFromSelect
// Two-pass extraction:
//   Pass 1 - FROM clause: handles comma-separated tables and
//             strips bare aliases (FROM customers c → CUSTOMERS).
//   Pass 2 - JOIN clauses: picks up every joined table regardless
//             of JOIN variant (INNER, LEFT, RIGHT, etc.).
// The final dedup pass preserves declaration order, which matters
// for the audit log readability.
// ---------------------------------------------------------------
std::vector<std::string> SqlAnalyzer::ExtractTablesFromSelect(
    const std::string& upper) const {
  std::vector<std::string> tables;

  {
    // Capture the FROM clause table list, stopping before any
    // JOIN/WHERE/GROUP/ORDER keyword or end of string e.g. "SELECT * FROM
    // customers c, orders o WHERE ..." → captures "customers c, orders o"
    std::regex from_rx(
        R"(FROM\s+([\w\s,]+?)(?=\s+(?:JOIN|LEFT|RIGHT|INNER|OUTER|CROSS|FULL|WHERE|GROUP|ORDER|HAVING|LIMIT)|$))");
    std::smatch m;

    if (std::regex_search(upper, m, from_rx)) {
      for (const auto& raw : SplitAndTrim(m[1].str(), ',')) {
        std::string t = FirstWord(Trim(raw));
        if (!t.empty()) {
          tables.push_back(t);
        }
      }
    }
  }

  // JOIN clauses - any JOIN variant followed by table name.
  // ranges::subrange lets us treat the sregex_iterator pair as a range and use
  // a range-for instead of a manual iterator loop.
  {
    // Match any JOIN variant and capture the table name that follows it
    // e.g. "LEFT JOIN order_items oi ON ..." → captures "ORDER_ITEMS"
    const std::regex join_rx(R"(JOIN\s+(\w+))");
    for (const auto& match : std::ranges::subrange(
             std::sregex_iterator(upper.begin(), upper.end(), join_rx),
             std::sregex_iterator{})) {
      tables.push_back(match[1].str());
    }
  }

  // Deduplicate while preserving order.
  // A JOIN table can also appear in the FROM clause - without this,
  // the policy engine would evaluate the same table twice.
  std::vector<std::string> seen;
  for (const auto& t : tables) {
    if (!std::ranges::contains(seen, t)) {
      seen.push_back(t);
    }
  }

  return seen;
}

// ---------------------------------------------------------------
// ExtractTablesFromDml
// Each DML type has a distinct syntactic position for its target
// table - INSERT INTO <table>, UPDATE <table> SET, DELETE FROM
// <table> - so each gets its own targeted regex rather than a
// generic fallback that could misfire.
// ---------------------------------------------------------------
std::vector<std::string> SqlAnalyzer::ExtractTablesFromDml(
    const std::string& upper, StatementType type) const {
  std::vector<std::string> tables;

  if (type == StatementType::kInsert) {
    // Capture the target table name from an INSERT statement
    // e.g. "INSERT INTO orders (customer_id) VALUES (1)" → captures "ORDERS"
    std::regex rx(R"(INSERT\s+INTO\s+(\w+))");
    std::smatch m;
    if (std::regex_search(upper, m, rx)) {
      tables.push_back(m[1].str());
    }
  } else if (type == StatementType::kUpdate) {
    // Capture the target table name from an UPDATE statement
    // e.g. "UPDATE orders SET created_at = NOW()" → captures "ORDERS"
    std::regex rx(R"(UPDATE\s+(\w+)\s+SET)");
    std::smatch m;
    if (std::regex_search(upper, m, rx)) {
      tables.push_back(m[1].str());
    }
  } else if (type == StatementType::kDelete) {
    // Capture the target table name from a DELETE statement
    // e.g. "DELETE FROM orders WHERE id = 1" → captures "ORDERS"
    std::regex rx(R"(DELETE\s+FROM\s+(\w+))");
    std::smatch m;
    if (std::regex_search(upper, m, rx)) {
      tables.push_back(m[1].str());
    }
  }

  return tables;
}

// ---------------------------------------------------------------
// ExtractTablesFromDdl
// DDL always names its target table after TABLE [...EXISTS].
// A single regex handles CREATE / ALTER / DROP uniformly - the
// optional IF [NOT] EXISTS clause is consumed but not captured.
// ---------------------------------------------------------------
std::vector<std::string> SqlAnalyzer::ExtractTablesFromDdl(
    const std::string& upper, StatementType /*type*/) const {
  std::vector<std::string> tables;

  // Match CREATE/ALTER/DROP TABLE statement, skipping optional IF [NOT] EXISTS,
  // and capture the table name e.g. "DROP TABLE IF EXISTS customers" → captures
  // "CUSTOMERS"
  const std::regex rx(
      R"((?:CREATE|ALTER|DROP)\s+TABLE\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?(\w+))");
  std::smatch m;

  if (std::regex_search(upper, m, rx)) {
    tables.push_back(m[1].str());
  }

  return tables;
}

// ---------------------------------------------------------------
// ExtractSelectColumns
// Extracts what the query is asking to *see* - used by the
// Classifier to detect PII exposure before execution, and by the
// AuditLogger to record exactly which columns were requested.
// Wildcard (*) is flagged separately so the Classifier can expand
// it against the registered schema rather than leaving it blank.
// ---------------------------------------------------------------
std::vector<std::string> SqlAnalyzer::ExtractSelectColumns(
    const std::string& upper, bool& out_wildcard) const {
  out_wildcard = false;
  std::vector<std::string> cols;

  // Capture everything between SELECT and FROM as the projection list (lazy
  // match) e.g. "SELECT name, email FROM customers" → captures "name, email"
  const std::regex rx(R"(SELECT\s+(.*?)\s+FROM)");
  std::smatch m;

  if (!std::regex_search(upper, m, rx)) {
    return cols;
  }

  std::string projection = Trim(m[1].str());

  // Wildcard - flag it and return early. The Classifier will expand
  // it using the registered schema for the referenced table.
  if (projection == "*") {
    out_wildcard = true;
    return cols;
  }

  for (auto& raw : SplitAndTrim(projection, ',')) {
    std::string col = raw;

    // Strip table prefix: CUSTOMERS.EMAIL → EMAIL
    auto dot = col.rfind('.');
    if (dot != std::string::npos) {
      col = col.substr(dot + 1);
    }

    // Match a column alias expression and capture only the source column name,
    // discarding the alias e.g. "EMAIL AS E" → captures "EMAIL"
    std::regex alias_rx(R"((\w+)\s+AS\s+\w+)");
    std::smatch am;
    if (std::regex_match(col, am, alias_rx)) {
      col = am[1].str();
    }

    col = Trim(col);
    if (!col.empty()) {
      cols.push_back(col);
    }
  }

  return cols;
}

// ---------------------------------------------------------------
// ExtractDmlColumns
// Extracts which columns a write operation touches - used in the
// audit log and by the Classifier to detect PII writes (e.g. an
// INSERT that includes an email column).
// ---------------------------------------------------------------
std::vector<std::string> SqlAnalyzer::ExtractDmlColumns(
    const std::string& upper, StatementType type) const {
  std::vector<std::string> cols;

  if (type == StatementType::kInsert) {
    // Match column list in: INSERT INTO table_name (col1, col2, ...) VALUES ...
    // e.g. "INSERT INTO customers (name, email, phone) VALUES (...)" → captures
    // "name, email, phone" Note: INSERT without an explicit column list (INSERT
    // INTO t VALUES ...) produces no match - columns remain empty. Documented
    // limitation.
    std::regex rx(R"(INSERT\s+INTO\s+\w+\s*\(([^)]+)\))");
    std::smatch m;
    if (std::regex_search(upper, m, rx)) {
      for (const auto& c : SplitAndTrim(m[1].str(), ',')) {
        if (!c.empty()) {
          cols.push_back(c);
        }
      }
    }
  } else if (type == StatementType::kUpdate) {
    // Match SET assignment list, stopping at WHERE clause or end of string
    // e.g. "UPDATE orders SET email='x', phone='y' WHERE id=1" → captures
    // "email='x', phone='y'"
    std::regex set_rx(R"(SET\s+(.+?)(?:\s+WHERE|$))");
    std::smatch m;
    if (std::regex_search(upper, m, set_rx)) {
      // Extract left-hand side column name from each assignment: col = value
      // e.g. "email='x', phone='y'" → iterates and captures "email", then
      // "phone"
      const std::regex assign_rx(R"((\w+)\s*=)");
      const std::string assignments = m[1].str();

      // ranges::subrange - iterate all SET assignments as a range
      for (const auto& match : std::ranges::subrange(
               std::sregex_iterator(assignments.begin(), assignments.end(),
                                    assign_rx),
               std::sregex_iterator{})) {
        cols.push_back(match[1].str());
      }
    }
  }

  return cols;
}

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------

// Trim - removes leading and trailing whitespace.
std::string SqlAnalyzer::Trim(const std::string& s) {
  auto is_space = [](char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
  };

  const auto first = std::ranges::find_if_not(s, is_space);
  const auto last =
      std::ranges::find_if_not(s | std::views::reverse, is_space).base();

  return (first >= last) ? std::string() : std::string(first, last);
}

// ToUpper - uppercases a copy of the string so all regex matching
// can be written in uppercase without case-insensitive flags.
std::string SqlAnalyzer::ToUpper(std::string s) {
  std::ranges::transform(s, s.begin(), [](unsigned char c) {
    return static_cast<char>(std::toupper(c));
  });
  return s;
}

// SplitAndTrim - splits on delim and trims each token.
// Used to break comma-separated column and table lists into
// individual names before further processing.
std::vector<std::string> SqlAnalyzer::SplitAndTrim(const std::string& s,
                                                   const char delim) {
  std::vector<std::string> result;
  std::stringstream ss(s);
  std::string token;

  while (std::getline(ss, token, delim)) {
    result.push_back(Trim(token));
  }

  return result;
}