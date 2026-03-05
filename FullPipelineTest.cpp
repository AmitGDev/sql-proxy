#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

#include "Classifier.hpp"
#include "PolicyEngine.hpp"
#include "SqlAnalyzer.hpp"
#include "UserManager.hpp"

namespace {

// ---------------------------------------------------------------
// EvaluateRequest
// Runs the full pipeline: user validation → SQL analysis →
// PII classification → policy decision.
// ---------------------------------------------------------------
void EvaluateRequest(const SqlAnalyzer& analyzer, const PolicyEngine& policy,
                     const UserManager& users, const Classifier& classifier,
                     const std::string& user, const std::string& sql) {
  std::cout << "------------------------------------------\n";
  std::cout << "| User   : " << user << "\n";
  std::cout << "| SQL    : " << sql << "\n";

  // 1. Validate user
  if (!users.Exists(user)) {
    std::cout << "| Decision: DENIED - Unknown user '" << user << "'\n";
    std::cout << "------------------------------------------\n\n";
    return;
  }

  const auto user_info = users.FindUser(user).value();
  std::cout << "| Role   : " << user_info.role << "\n";

  // 2. Analyze SQL
  const AnalysisResult result = analyzer.Analyze(sql);
  std::cout << "| Type   : " << ToString(result.type) << "\n";

  std::cout << "| Tables : ";
  if (result.tables.empty()) {
    std::cout << "(none)";
  } else {
    for (size_t i = 0; i < result.tables.size(); ++i)
      std::cout << (i ? ", " : "") << result.tables[i];
  }
  std::cout << "\n";

  std::cout << "| Columns: ";
  if (result.is_wildcard) {
    std::cout << "* (wildcard)";
  } else if (result.columns.empty()) {
    std::cout << "(none)";
  } else {
    for (size_t i = 0; i < result.columns.size(); ++i)
      std::cout << (i ? ", " : "") << result.columns[i];
  }
  std::cout << "\n";

  // 3. Classify PII exposure
  std::vector<std::string> all_tags;
  if (result.is_wildcard) {
    // Wildcard: check every referenced table's full column set
    for (const auto& table : result.tables) {
      const auto cr = classifier.Classify({}, /*is_wildcard=*/true, table);
      for (const auto& tag : cr.tags)
        if (std::find(all_tags.begin(), all_tags.end(), tag) == all_tags.end())
          all_tags.push_back(tag);
    }
  } else {
    all_tags = classifier.Classify(result.columns).tags;
  }

  std::cout << "| PII    : ";
  if (all_tags.empty()) {
    std::cout << "none";
  } else {
    for (size_t i = 0; i < all_tags.size(); ++i)
      std::cout << (i ? ", " : "") << all_tags[i];
  }
  std::cout << "\n";

  // 4. Policy decision
  const PolicyDecision decision = policy.Evaluate(user, result);
  std::cout << "| Decision: " << (decision.allowed ? "ALLOWED" : "DENIED")
            << " - " << decision.reason << "\n";
  std::cout << "------------------------------------------\n\n";
}

}  // namespace

// ---------------------------------------------------------------
// FullPipelineTest (Entry point for this test case)
// ---------------------------------------------------------------
int FullPipelineTest() {
  SqlAnalyzer analyzer;
  PolicyEngine policy;
  UserManager users;
  Classifier classifier;

  // Register schema so SELECT * can detect PII per table
  classifier.RegisterTableColumns("customers",
                                  {"id", "name", "email", "phone"});
  classifier.RegisterTableColumns("orders",
                                  {"id", "customer_id", "created_at"});
  classifier.RegisterTableColumns(
      "order_items",
      {"id", "order_id", "product_id", "quantity", "unit_price"});
  classifier.RegisterTableColumns("products", {"id", "name", "price"});

  // Load PII classification rules (falls back to built-in defaults if missing)
  try {
    classifier.LoadFromFile("classifier.json");
  } catch (const std::exception& e) {
    std::cerr << "Warning: " << e.what() << " - using built-in PII defaults.\n";
    classifier.LoadDefaults();
  }

  // Load users (falls back to hardcoded if file missing)
  try {
    users.LoadFromFile("users.json");
  } catch (const std::exception& e) {
    std::cerr << "Warning: " << e.what() << " - using hardcoded users.\n\n";
    users.AddUser({"alice", "analyst"});
    users.AddUser({"bob", "readonly"});
    users.AddUser({"admin", "admin"});
  }

  // Load policies (falls back to hardcoded if file missing)
  try {
    policy.LoadFromFile("policies.json");
  } catch (const std::exception& e) {
    std::cerr << "Warning: " << e.what() << " - using hardcoded rules.\n\n";
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

  users.PrintUsers();
  policy.PrintRules();

  std::cout << "=== Full Pipeline Tests ===\n\n";

  // alice - SELECT with PII columns
  EvaluateRequest(analyzer, policy, users, classifier, "alice",
                  "SELECT name, email FROM customers");

  // alice - SELECT * expands to full schema PII check
  EvaluateRequest(analyzer, policy, users, classifier, "alice",
                  "SELECT * FROM customers");

  // alice - multi-table JOIN, no PII columns projected
  EvaluateRequest(analyzer, policy, users, classifier, "alice",
                  "SELECT c.name, o.id, p.name "
                  "FROM customers c "
                  "JOIN orders o ON o.customer_id = c.id "
                  "JOIN products p ON p.id = o.product_id");

  // alice - INSERT (no PII)
  EvaluateRequest(analyzer, policy, users, classifier, "alice",
                  "INSERT INTO orders (customer_id) VALUES (1)");

  // alice - DDL blocked
  EvaluateRequest(analyzer, policy, users, classifier, "alice",
                  "DROP TABLE customers");

  // bob - allowed, no PII
  EvaluateRequest(analyzer, policy, users, classifier, "bob",
                  "SELECT name, price FROM products");

  // bob - blocked: customers is PII-restricted for bob
  EvaluateRequest(analyzer, policy, users, classifier, "bob",
                  "SELECT name, email FROM customers");

  // admin - allowed, both PII tags exposed
  EvaluateRequest(analyzer, policy, users, classifier, "admin",
                  "SELECT name, email, phone FROM customers");

  // unknown user - rejected before policy check
  EvaluateRequest(analyzer, policy, users, classifier, "eve",
                  "SELECT * FROM products");

  return 0;
}