#include <iostream>
#include <string>
#include <vector>

#include "PolicyEngine.hpp"
#include "SqlAnalyzer.hpp"

namespace {

// ---------------------------------------------------------------
// Print analysis + policy decision together
// ---------------------------------------------------------------
void Evaluate(const SqlAnalyzer& analyzer, const PolicyEngine& policy,
              const std::string& user, const std::string& sql) {
  AnalysisResult r = analyzer.Analyze(sql);
  PolicyDecision d = policy.Evaluate(user, r);

  std::cout << "------------------------------------------\n";
  std::cout << "| User   : " << user << "\n";
  std::cout << "| SQL    : " << r.raw_sql << "\n";
  std::cout << "| Type   : " << ToString(r.type) << "\n";

  std::cout << "| Tables : ";
  for (size_t i = 0; i < r.tables.size(); ++i)
    std::cout << (i ? ", " : "") << r.tables[i];
  if (r.tables.empty()) std::cout << "(none)";
  std::cout << "\n";

  std::cout << "| Columns: ";
  if (r.is_wildcard)
    std::cout << "* (wildcard)";
  else {
    for (size_t i = 0; i < r.columns.size(); ++i)
      std::cout << (i ? ", " : "") << r.columns[i];
    if (r.columns.empty()) std::cout << "(none)";
  }
  std::cout << "\n";

  std::cout << "| Decision: " << (d.allowed ? "ALLOWED" : "DENIED") << " - "
            << d.reason << "\n";
  std::cout << "------------------------------------------\n\n";
}

}  // namespace

int PolicyEngineTest() {
  SqlAnalyzer analyzer;
  PolicyEngine policy;

  // Load rules from file - copy policies.json next to your .exe
  // or adjust the path below.
  try {
    policy.LoadFromFile("config\\policies.json");
  } catch (const std::exception& e) {
    std::cerr << "Failed to load policies.json: " << e.what() << "\n"
              << "Falling back to hardcoded test rules.\n\n";

    // Hardcoded fallback so the test still runs without the file
    policy.AddRule(
        {"alice", "*", {StatementType::kSelect}, PolicyEffect::kAllow});
    policy.AddRule(
        {"alice",
         "orders",
         {StatementType::kInsert, StatementType::kUpdate, StatementType::kDelete},
         PolicyEffect::kAllow});
    policy.AddRule(
        {"bob", "products", {StatementType::kSelect}, PolicyEffect::kAllow});
    policy.AddRule(
        {"bob", "orders", {StatementType::kSelect}, PolicyEffect::kAllow});
    policy.AddRule({"bob", "customers", {}, PolicyEffect::kBlock});
    policy.AddRule({"admin", "*", {}, PolicyEffect::kAllow});
    policy.AddRule({"*", "*", {}, PolicyEffect::kBlock});
  }

  policy.PrintRules();

  std::cout << "=== Policy Evaluation Tests ===\n\n";

  // alice - allowed: SELECT on any table
  Evaluate(analyzer, policy, "alice", "SELECT name, email FROM customers");

  // alice - allowed: multi-table JOIN
  Evaluate(analyzer, policy, "alice",
           "SELECT c.name, o.id, p.name "
           "FROM customers c "
           "JOIN orders o ON o.customer_id = c.id "
           "JOIN products p ON p.id = o.product_id");

  // alice - allowed: INSERT into orders
  Evaluate(analyzer, policy, "alice",
           "INSERT INTO orders (customer_id) VALUES (1)");

  // alice - DENIED: DDL blocked
  Evaluate(analyzer, policy, "alice", "DROP TABLE customers");

  // bob - allowed: SELECT on products
  Evaluate(analyzer, policy, "bob", "SELECT name, price FROM products");

  // bob - DENIED: customers is PII-blocked for bob
  Evaluate(analyzer, policy, "bob", "SELECT name, email FROM customers");

  // bob - DENIED: UPDATE not in bob's allowed types
  Evaluate(analyzer, policy, "bob",
           "UPDATE orders SET amount = 999 WHERE id = 1");

  // admin - allowed: everything
  Evaluate(analyzer, policy, "admin", "DROP TABLE order_items");

  // unknown user - DENIED: no rules match, default deny
  Evaluate(analyzer, policy, "eve", "SELECT * FROM products");

  return 0;
}