// Standard library headers
#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

// Project headers
#include "AuditLogger.hpp"
#include "Classifier.hpp"
#include "DbExecutor.hpp"
#include "PolicyEngine.hpp"
#include "SqlAnalyzer.hpp"
#include "UserManager.hpp"

namespace {

// ---------------------------------------------------------------
// ProxyRequest - one incoming request to the proxy
// ---------------------------------------------------------------
struct ProxyRequest {
  std::string user;
  std::string sql;
};

// ---------------------------------------------------------------
// PipelineResult
// Everything the pipeline produced for one request.
// Consumed by PrintResult() and AuditLogger - neither needs to
// know how the values were derived.
// ---------------------------------------------------------------
struct PipelineResult {
  // Input echo
  std::string user;
  std::string sql;
  std::string role;

  // Analysis
  AnalysisResult analysis;

  // Classification
  std::vector<std::string> pii_tags;

  // Decision
  bool allowed = false;
  std::string deny_reason;

  // Execution (SELECT only)
  std::vector<std::string> column_names;
  QueryResult rows;

  // Execution (DML/DDL)
  int affected_rows = 0;

  // Error
  bool db_error = false;
  std::string db_error_msg;
};

// ---------------------------------------------------------------
// ProcessRequest
// Pure pipeline - no output. Returns a fully populated
// PipelineResult. The caller decides what to do with it
// (print, audit, both, neither).
// ---------------------------------------------------------------
PipelineResult ProcessRequest(const ProxyRequest& req,
                              const SqlAnalyzer& analyzer,
                              const PolicyEngine& policy,
                              const UserManager& users,
                              const Classifier& classifier,
                              const DbExecutor& db) {
  PipelineResult result;
  result.user = req.user;
  result.sql = req.sql;

  // ── 1. Validate user ───────────────────────────────────────
  if (!users.Exists(req.user)) {
    result.allowed = false;
    result.deny_reason = "Unknown user '" + req.user + "'";
    result.role = "UNKNOWN";
    result.analysis.type = StatementType::kUnknown;
    result.analysis.raw_sql = req.sql;
    return result;
  }

  result.role = users.FindUser(req.user).value().role;

  // ── 2. Analyze SQL ─────────────────────────────────────────
  result.analysis = analyzer.Analyze(req.sql);

  // ── 3. Classify PII ────────────────────────────────────────
  if (result.analysis.is_wildcard) {
    for (const auto& table : result.analysis.tables) {
      const auto cr = classifier.Classify({}, /*is_wildcard=*/true, table);
      for (const auto& tag : cr.tags)
        if (std::find(result.pii_tags.begin(), result.pii_tags.end(), tag) ==
            result.pii_tags.end())
          result.pii_tags.push_back(tag);
    }
  } else {
    result.pii_tags = classifier.Classify(result.analysis.columns).tags;
  }

  // ── 4. Evaluate policy ─────────────────────────────────────
  const PolicyDecision decision = policy.Evaluate(req.user, result.analysis);
  result.allowed = decision.allowed;
  result.deny_reason = decision.reason;

  if (!result.allowed) {
    return result;
  }

  // ── 5. Execute ─────────────────────────────────────────────
  try {
    if (result.analysis.type == StatementType::kSelect) {
      result.rows = db.ExecuteSelect(req.sql);
      result.column_names = db.LastColumnNames();

      // Re-classify from actual DB column names - catches wildcard aliases
      const auto actual_pii = classifier.Classify(result.column_names).tags;
      for (const auto& tag : actual_pii)
        if (std::ranges::find(result.pii_tags, tag) == result.pii_tags.end()) {
          result.pii_tags.push_back(tag);
        }
    } else {
      result.affected_rows = db.ExecuteNonQuery(req.sql);
    }
  } catch (const std::exception& e) {
    result.db_error = true;
    result.db_error_msg = e.what();
    result.allowed = false;
    result.deny_reason = std::string("DB error: ") + e.what();
  }

  return result;
}

// ---------------------------------------------------------------
// PrintResult
// Pure display - no logic. Reads PipelineResult and formats
// it for the console. Business decisions already made.
// ---------------------------------------------------------------
void PrintResult(const PipelineResult& r) {
  std::cout << "==========================================\n";
  std::cout << "  User : " << r.user << "\n";
  std::cout << "  SQL  : " << r.sql << "\n";
  std::cout << "------------------------------------------\n";
  std::cout << "  Role   : " << r.role << "\n";
  std::cout << "  Type   : " << ToString(r.analysis.type) << "\n";

  std::cout << "  Tables : ";
  if (r.analysis.tables.empty()) {
    std::cout << "(none)";
  } else {
    for (size_t i = 0; i < r.analysis.tables.size(); ++i) {
      std::cout << (i ? ", " : "") << r.analysis.tables[i];
    }
  }
  std::cout << "\n";

  std::cout << "  Columns: ";
  if (r.analysis.is_wildcard) {
    std::cout << "* (wildcard)";
  } else if (r.analysis.columns.empty()) {
    std::cout << "(none)";
  } else {
    for (size_t i = 0; i < r.analysis.columns.size(); ++i) {
      std::cout << (i ? ", " : "") << r.analysis.columns[i];
    }
  }
  std::cout << "\n";

  std::cout << "  PII    : ";
  if (r.pii_tags.empty()) {
    std::cout << "none";
  } else {
    for (size_t i = 0; i < r.pii_tags.size(); ++i) {
      std::cout << (i ? ", " : "") << r.pii_tags[i];
    }
  }
  std::cout << "\n";

  if (!r.allowed) {
    std::cout << "  [DENIED] " << r.deny_reason << "\n\n";
    return;
  }

  if (r.analysis.type == StatementType::kSelect) {
    std::cout << "  [ALLOWED] " << r.rows.size() << " row(s) returned.\n";

    // Column headers
    for (size_t i = 0; i < r.column_names.size(); ++i)
      std::cout << (i ? " | " : "  ") << r.column_names[i];
    std::cout << "\n  ";
    for (size_t i = 0; i < r.column_names.size(); ++i) {
      std::cout << (i ? "-+-" : "")
                << std::string(r.column_names[i].size(), '-');
    }
    std::cout << "\n";

    // Rows
    for (const auto& row : r.rows) {
      for (size_t i = 0; i < row.size(); ++i) {
        std::cout << (i ? " | " : "  ") << row[i];
      }
      std::cout << "\n";
    }
  } else {
    std::cout << "  [ALLOWED] Statement executed. " << r.affected_rows
              << " row(s) affected.\n";
  }

  std::cout << "\n";
}

}  // namespace

// ---------------------------------------------------------------
// ExecuteTest
// ---------------------------------------------------------------
int ExecuteTest() {
  // ── Component setup ────────────────────────────────────────
  SqlAnalyzer analyzer;
  PolicyEngine policy;
  UserManager users;
  Classifier classifier;

  // Load table schema for wildcard PII expansion
  try {
    classifier.LoadSchemaFromFile("config\\schema.json");
    std::cout << "Schema loaded from schema.json\n";
  } catch (const std::exception& e) {
    std::cerr << "Warning: " << e.what()
              << " - using built-in schema defaults.\n";
    classifier.LoadSchemaDefaults();
  }

  // Load PII classification rules
  try {
    classifier.LoadFromFile("config\\classifier.json");
    std::cout << "PII rules loaded from classifier.json\n";
  } catch (const std::exception& e) {
    std::cerr << "Warning: " << e.what() << " - using built-in PII defaults.\n";
    classifier.LoadDefaults();
  }

  // Load users
  try {
    users.LoadFromFile("config\\users.json");
  } catch (const std::exception& e) {
    std::cerr << "Warning: " << e.what() << " - using hardcoded users.\n";
    users.AddUser({"alice", "analyst"});
    users.AddUser({"bob", "readonly"});
    users.AddUser({"admin", "admin"});
  }

  // Load policies
  try {
    policy.LoadFromFile("config\\policies.json");
  } catch (const std::exception& e) {
    std::cerr << "Warning: " << e.what() << " - using hardcoded rules.\n";
    policy.AddRule(
        {"alice", "*", {StatementType::kSelect}, PolicyEffect::kAllow});
    policy.AddRule({"alice",
                    "orders",
                    {StatementType::kInsert, StatementType::kUpdate,
                     StatementType::kDelete},
                    PolicyEffect::kAllow});
    policy.AddRule(
        {"bob", "products", {StatementType::kSelect}, PolicyEffect::kAllow});
    policy.AddRule(
        {"bob", "orders", {StatementType::kSelect}, PolicyEffect::kAllow});
    policy.AddRule({"bob", "customers", {}, PolicyEffect::kBlock});
    policy.AddRule({"admin", "*", {}, PolicyEffect::kAllow});
    policy.AddRule({"*", "*", {}, PolicyEffect::kBlock});
  }

  // Connect to database
  const std::string kConnStr =
      "host=localhost port=5432 dbname=testdb user=postgres password=postgres";
  DbExecutor db(kConnStr);
  std::cout << "Database connected: " << (db.IsConnected() ? "YES" : "NO")
            << "\n\n";

  // Open audit log
  AuditLogger audit("audit.jsonl");
  std::cout << "Audit log: audit.jsonl\n\n";

  // ── Test requests ───────────────────────────────────────────
  const std::vector<ProxyRequest> requests = {
      {"alice", "SELECT name, email FROM customers"},
      {"alice", "SELECT * FROM customers"},
      {"alice",
       "SELECT c.name, o.id, p.name, oi.quantity, oi.unit_price "
       "FROM customers c "
       "JOIN orders o ON o.customer_id = c.id "
       "JOIN order_items oi ON oi.order_id = o.id "
       "JOIN products p ON p.id = oi.product_id"},
      {"bob", "SELECT name, price FROM products"},
      {"bob", "SELECT name, email FROM customers"},
      {"alice", "INSERT INTO orders (customer_id) VALUES (1)"},
      {"alice", "UPDATE orders SET created_at = NOW() WHERE id = 1"},
      {"alice", "DROP TABLE customers"},
      {"admin", "SELECT name, email, phone FROM customers"},
      {"eve", "SELECT * FROM products"},
  };

  for (const auto& req : requests) {
    const PipelineResult result =
        ProcessRequest(req, analyzer, policy, users, classifier, db);
    PrintResult(result);
    audit.Log(AuditLogger::BuildRecord(
        result.user, result.role, result.analysis, result.pii_tags,
        result.allowed, result.deny_reason, result.affected_rows));
  }

  std::cout << "==========================================\n";
  std::cout
      << "All requests processed. See audit.jsonl for full audit trail.\n";

  return 0;
}