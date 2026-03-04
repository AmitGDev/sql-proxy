#pragma once
#include <string>
#include <vector>

#include "SqlAnalyzer.hpp"

// ---------------------------------------------------------------
// PolicyEffect - what the rule does
// ---------------------------------------------------------------
enum class PolicyEffect { kAllow, kBlock };

// ---------------------------------------------------------------
// PolicyRule
// Specificity (highest to lowest):
//   1. user + table  - e.g. alice can SELECT on customers
//   2. user + "*"    - e.g. alice can SELECT on any table
//   3. "*"  + table  - e.g. any user can SELECT on products
//   4. "*"  + "*"    - global default
//
// statement_types: empty vector = applies to ALL statement types.
// ---------------------------------------------------------------
struct PolicyRule {
  std::string user;   // "*" = any user (stored uppercase)
  std::string table;  // "*" = any table (stored uppercase)
  std::vector<StatementType> statement_types;  // empty = all types
  PolicyEffect effect = PolicyEffect::kBlock;
};

// ---------------------------------------------------------------
// PolicyDecision - result of evaluating rules for one request
// ---------------------------------------------------------------
struct PolicyDecision {
  bool allowed = false;
  std::string reason;  // human-readable explanation
};

// ---------------------------------------------------------------
// PolicyEngine
//
// Evaluation priority:
//   1. Most specific match wins  (user+table > user+* > *+table > *+*)
//   2. Among equally specific rules, BLOCK beats ALLOW
//   3. No match → DENY (default-deny)
// ---------------------------------------------------------------
class PolicyEngine {
 public:
  // Load rules from a JSON file. See policies.json for format.
  void LoadFromFile(const std::string& path);

  // Add a rule programmatically (useful for tests).
  void AddRule(PolicyRule rule);

  // Evaluate all rules for a given user + analysis result.
  PolicyDecision Evaluate(const std::string& user,
                          const AnalysisResult& analysis) const;

  // Dump all loaded rules to stdout (debugging helper).
  void PrintRules() const;

 private:
  std::vector<PolicyRule> rules_;

  // Returns 0–3: higher = more specific match for (user, table). -1 = no match.
  int Specificity(const PolicyRule& rule, const std::string& user,
                  const std::string& table) const;
};