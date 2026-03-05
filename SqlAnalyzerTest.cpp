#include <iostream>
#include <string>
#include <vector>

#include "SqlAnalyzer.hpp"

namespace {

// ---------------------------------------------------------------
// Print a single AnalysisResult in a readable way
// ---------------------------------------------------------------
void PrintResult(const AnalysisResult& r) {
  std::cout << "------------------------------------------\n";
  std::cout << "| SQL    : " << r.raw_sql << "\n";
  std::cout << "| Type   : " << ToString(r.type) << "\n";

  std::cout << "| Tables : ";
  if (r.tables.empty()) std::cout << "(none)";
  for (size_t i = 0; i < r.tables.size(); ++i)
    std::cout << (i ? ", " : "") << r.tables[i];
  std::cout << "\n";

  std::cout << "| Columns: ";
  if (r.is_wildcard) {
    std::cout << "* (wildcard)";
  } else if (r.columns.empty()) {
    std::cout << "(none / not applicable)";
  } else {
    for (size_t i = 0; i < r.columns.size(); ++i)
      std::cout << (i ? ", " : "") << r.columns[i];
  }
  std::cout << "\n";
  std::cout << "------------------------------------------\n\n";
}

}  // namespace

int SqlAnalyzerTest() {
  SqlAnalyzer analyzer;

  std::vector<std::string> test_queries = {
      // SELECT - wildcard
      "SELECT * FROM customers",

      // SELECT - specific columns
      "SELECT name, email FROM customers",

      // SELECT - with table prefix and alias
      "SELECT c.name AS customer_name, c.email FROM customers c",

      // SELECT - multi-table JOIN (the big query from our schema)
      "SELECT c.name, o.id, p.name, oi.quantity, oi.unit_price "
      "FROM customers c "
      "JOIN orders o ON o.customer_id = c.id "
      "JOIN order_items oi ON oi.order_id = o.id "
      "JOIN products p ON p.id = oi.product_id",

      // DML - INSERT with column list
      "INSERT INTO customers (name, email, phone) VALUES ('Eve', "
      "'eve@example.com', '555-0105')",

      // DML - INSERT without column list
      "INSERT INTO orders VALUES (6, 1, NOW())",

      // DML - UPDATE
      "UPDATE customers SET email = 'new@example.com', phone = '555-9999' "
      "WHERE id = 1",

      // DML - DELETE
      "DELETE FROM orders WHERE id = 3",

      // DDL - CREATE
      "CREATE TABLE shipping_addresses (id SERIAL PRIMARY KEY, customer_id "
      "INTEGER, address TEXT)",

      // DDL - ALTER
      "ALTER TABLE customers ADD COLUMN loyalty_points INTEGER DEFAULT 0",

      // DDL - DROP
      "DROP TABLE IF EXISTS shipping_addresses",
  };

  std::cout << "\n=== SqlAnalyzer Test Harness ===\n\n";
  for (const auto& query : test_queries) {
    PrintResult(analyzer.Analyze(query));
  }

  return 0;
}