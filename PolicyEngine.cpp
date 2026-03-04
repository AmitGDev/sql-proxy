#include "PolicyEngine.hpp"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <utility>

#include "Utility.hpp"

// ---------------------------------------------------------------
// File-local helpers
// ---------------------------------------------------------------
namespace {

StatementType ParseStatementType(const std::string& statement) {
  const std::string upper = ToUpper(statement);

  if (upper == "SELECT") {
    return StatementType::kSelect;
  }
  if (upper == "INSERT") {
    return StatementType::kInsert;
  }
  if (upper == "UPDATE") {
    return StatementType::kUpdate;
  }
  if (upper == "DELETE") {
    return StatementType::kDelete;
  }
  if (upper == "CREATE") {
    return StatementType::kCreate;
  }
  if (upper == "ALTER") {
    return StatementType::kAlter;
  }
  if (upper == "DROP") {
    return StatementType::kDrop;
  }

  throw std::runtime_error("Unknown statement type in policy: " + statement);
}

}  // namespace

// ---------------------------------------------------------------
// LoadFromFile
//
// Expected JSON format:
// {
//   "rules": [
//     {
//       "user":           "alice",
//       "table":          "customers",
//       "statementTypes": ["SELECT"],   // omit or [] for all types
//       "effect":         "ALLOW"
//     }
//   ]
// }
// ---------------------------------------------------------------
void PolicyEngine::LoadFromFile(const std::string& path) {
  std::ifstream file(path);
  if (!file.is_open()) {
    throw std::runtime_error("Cannot open policy file: " + path);
  }

  nlohmann::json json;
  file >> json;

  for (const auto& item : json.at("rules")) {
    PolicyRule rule;
    rule.user = ToUpper(item.at("user").get<std::string>());
    rule.table = ToUpper(item.at("table").get<std::string>());
    rule.effect = (ToUpper(item.at("effect").get<std::string>()) == "ALLOW")
                      ? PolicyEffect::kAllow
                      : PolicyEffect::kBlock;

    if (item.contains("statementTypes")) {
      for (const auto& st : item["statementTypes"]) {
        rule.statement_types.push_back(
            ParseStatementType(st.get<std::string>()));
      }
    }

    rules_.push_back(std::move(rule));
  }
}

// ---------------------------------------------------------------
// AddRule
// ---------------------------------------------------------------
void PolicyEngine::AddRule(PolicyRule rule) {
  rule.user = ToUpper(rule.user);
  rule.table = ToUpper(rule.table);
  rules_.push_back(std::move(rule));
}

// ---------------------------------------------------------------
// Specificity
// ---------------------------------------------------------------
int PolicyEngine::Specificity(const PolicyRule& rule, const std::string& user,
                              const std::string& table) const {
  const bool user_match = (rule.user == "*" || rule.user == user);
  const bool table_match = (rule.table == "*" || rule.table == table);

  if (!user_match || !table_match) {
    return -1;  // No match
  }

  int score = 0;
  if (rule.user != "*") {
    score += 2;  // Specific user is worth more
  }
  if (rule.table != "*") {
    score += 1;  // Specific table is worth more
  }
  return score;
}

// ---------------------------------------------------------------
// Evaluate
// ---------------------------------------------------------------
PolicyDecision PolicyEngine::Evaluate(const std::string& user,
                                      const AnalysisResult& analysis) const {
  const std::string upper_user = ToUpper(user);

  if (analysis.tables.empty()) {
    return {false, "No tables identified in statement - denied by default."};
  }

  // Find the best matching rule (fail-fast evaluation).
  // engine makes one final ALLOW/BLOCK decision for the whole query,
  // but it evaluates each table separately first.
  for (const auto& raw_table : analysis.tables) {
    const std::string table = ToUpper(raw_table);

    // No match yet
    int best_score = -1;
    PolicyEffect best_effect = PolicyEffect::kBlock;  // default-deny

    for (const auto& rule : rules_) {
      int score = Specificity(rule, upper_user, table);
      if (score < 0) {
        continue;  // Skip non-matching rules
      }

      // Check statement type match (empty = all types)
      if (!rule.statement_types.empty()) {
        bool type_match =
            std::find(rule.statement_types.begin(), rule.statement_types.end(),
                      analysis.type) != rule.statement_types.end();
        if (!type_match) {
          continue;
        }
      }

      // Higher specificity wins; ties broken by BLOCK > ALLOW
      if (score > best_score ||
          (score == best_score && rule.effect == PolicyEffect::kBlock)) {
        best_score = score;
        best_effect = rule.effect;
      }
    }

    if (best_score == -1) {
      return {false, "No policy rule matched for user='" + user + "' table='" +
                         raw_table + "' - default deny."};
    }

    if (best_effect == PolicyEffect::kBlock) {
      return {false, "Access BLOCKED for user='" + user + "' on table='" +
                         raw_table + "'."};
    }
  }

  return {true, "Access ALLOWED for user='" + user + "'."};
}

// ---------------------------------------------------------------
// PrintRules
// ---------------------------------------------------------------
void PolicyEngine::PrintRules() const {
  std::cout << "=== Loaded Policy Rules ===\n";
  for (const auto& r : rules_) {
    std::cout << "  user=" << r.user << "  table=" << r.table << "  effect="
              << (r.effect == PolicyEffect::kAllow ? "ALLOW" : "BLOCK")
              << "  types=";
    if (r.statement_types.empty()) {
      std::cout << "ALL";
    } else {
      for (size_t i = 0; i < r.statement_types.size(); ++i) {
        std::cout << (i ? "," : "") << ToString(r.statement_types[i]);
      }
    }
    std::cout << "\n";
  }
  std::cout << "===========================\n\n";
}