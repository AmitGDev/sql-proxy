// Header corresponding to the.cpp file
#include "Classifier.hpp"

// Standard library headers
#include <algorithm>
#include <fstream>
#include <stdexcept>
#include <vector>

// Third-party headers
#include <nlohmann/json.hpp>

// Project headers
#include "Utility.hpp"

// ---------------------------------------------------------------
// LoadFromFile
//
// Expected classifier.json format:
// {
//   "rules": [
//     {
//       "patterns": ["EMAIL", "EMAIL_ADDRESS", "USER_EMAIL"],
//       "tag":      "PII.Email"
//     },
//     {
//       "patterns": ["PHONE", "PHONE_NUMBER", "MOBILE"],
//       "tag":      "PII.Phone"
//     }
//   ]
// }
//
// Patterns are matched case-insensitively (normalised to uppercase).
// Tags are arbitrary strings - add new PII categories freely.
// ---------------------------------------------------------------
void Classifier::LoadFromFile(const std::string& path) {
  std::ifstream file(path);
  if (!file.is_open()) {
    throw std::runtime_error("Cannot open classifier config: " + path);
  }

  nlohmann::json json;
  file >> json;

  rules_.clear();
  for (const auto& item : json.at("rules")) {
    PiiRule rule;
    rule.tag = item.at("tag").get<std::string>();
    for (const auto& p : item.at("patterns")) {
      rule.patterns.push_back(ToUpper(p.get<std::string>()));
    }
    rules_.push_back(std::move(rule));
  }
}

// ---------------------------------------------------------------
// LoadDefaults
// Built-in fallback - mirrors what classifier.json ships with.
// Keeps the service functional if the config file is missing.
// ---------------------------------------------------------------
void Classifier::LoadDefaults() {
  rules_.clear();
  rules_.push_back({{"EMAIL", "EMAIL_ADDRESS", "EMAILADDRESS", "USER_EMAIL",
                     "CONTACT_EMAIL"},
                    "PII.Email"});

  rules_.push_back({{"PHONE", "PHONE_NUMBER", "PHONENUMBER", "MOBILE",
                     "MOBILE_NUMBER", "CONTACT_PHONE"},
                    "PII.Phone"});
}

// ---------------------------------------------------------------
// LoadSchemaFromFile
//
// Expected schema.json format:
// {
//   "tables": [
//     { "name": "customers",   "columns": ["id", "name", "email", "phone"] },
//     { "name": "orders",      "columns": ["id", "customer_id", "created_at"] }
//   ]
// }
//
// ---------------------------------------------------------------
void Classifier::LoadSchemaFromFile(const std::string& path) {
  std::ifstream file(path);
  if (!file.is_open())
    throw std::runtime_error("Cannot open schema config: " + path);

  nlohmann::json json;
  file >> json;

  schema_.clear();
  for (const auto& table : json.at("tables")) {
    const std::string name = table.at("name").get<std::string>();
    std::vector<std::string> cols;
    for (const auto& c : table.at("columns"))
      cols.push_back(c.get<std::string>());
    RegisterTableColumns(name, cols);
  }
}

// ---------------------------------------------------------------
// LoadSchemaDefaults
// Built-in fallback - mirrors what schema.json ships with.
// Keeps wildcard PII expansion functional if the config is missing.
// ---------------------------------------------------------------
void Classifier::LoadSchemaDefaults() {
  schema_.clear();
  RegisterTableColumns("customers", {"id", "name", "email", "phone"});
  RegisterTableColumns("orders", {"id", "customer_id", "created_at"});
  RegisterTableColumns("order_items", {"id", "order_id", "product_id",
                                       "quantity", "unit_price"});
  RegisterTableColumns("products", {"id", "name", "price"});
}

void Classifier::RegisterTableColumns(const std::string& table_name,
                                      const std::vector<std::string>& columns) {
  const std::string upper_table = ToUpper(table_name);
  std::vector<std::string> upper_cols;
  upper_cols.reserve(columns.size());
  for (const auto& c : columns) {
    upper_cols.push_back(ToUpper(c));
  }
  schema_.emplace_back(upper_table, std::move(upper_cols));
}

// ---------------------------------------------------------------
// Classify
// ---------------------------------------------------------------
ClassificationResult Classifier::Classify(
    const std::vector<std::string>& columns, bool is_wildcard,
    const std::string& table_name) const {
  ClassificationResult result;
  std::vector<std::string> to_check;

  if (is_wildcard && !table_name.empty()) {
    // Expand wildcard: inspect all known columns for this table
    to_check = ColumnsForTable(ToUpper(table_name));
  } else {
    for (const auto& c : columns) {
      to_check.push_back(ToUpper(c));
    }
  }

  for (const auto& col : to_check) {
    for (const auto& tag : ClassifyColumn(col)) {
      // Deduplicate tags
      if (std::find(result.tags.begin(), result.tags.end(), tag) ==
          result.tags.end()) {
        result.tags.push_back(tag);
      }
    }
  }

  return result;
}

// ---------------------------------------------------------------
// ClassifyColumn
// Iterates loaded rules and returns all matching tags.
// ---------------------------------------------------------------
std::vector<std::string> Classifier::ClassifyColumn(
    const std::string& upper_col) const {
  std::vector<std::string> tags;
  for (const auto& rule : rules_) {
    if (std::find(rule.patterns.begin(), rule.patterns.end(), upper_col) !=
        rule.patterns.end()) {
      tags.push_back(rule.tag);
    }
  }
  return tags;
}

// ---------------------------------------------------------------
// ColumnsForTable
// ---------------------------------------------------------------
std::vector<std::string> Classifier::ColumnsForTable(
    const std::string& upper_table) const {
  for (const auto& [table, cols] : schema_) {
    if (table == upper_table) {
      return cols;
    }
  }
  return {};
}
