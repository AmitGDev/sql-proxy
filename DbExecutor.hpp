#pragma once
#include <string>
#include <vector>

// ---------------------------------------------------------------
// QueryRow    - one row as a list of string values
// QueryResult - full result set returned from a SELECT
// ---------------------------------------------------------------
using QueryRow = std::vector<std::string>;
using QueryResult = std::vector<QueryRow>;

// ---------------------------------------------------------------
// DbExecutor
//
// Wraps a libpqxx connection.
// - SELECT statements are executed and rows returned.
// - DDL / DML statements are executed inside a transaction
//   and committed if successful.
// - All errors are surfaced as std::runtime_error.
// ---------------------------------------------------------------
class DbExecutor {
 public:
  // Construct with a libpqxx connection string.
  // e.g. "host=localhost port=5432 dbname=testdb user=postgres
  // password=postgres"
  explicit DbExecutor(const std::string& connection_string);

  // Execute a SELECT - returns all rows as strings.
  // Throws on error.
  QueryResult ExecuteSelect(const std::string& sql) const;

  // Execute a DDL or DML statement inside a transaction.
  // Returns the number of affected rows (0 for DDL).
  // Throws on error.
  int ExecuteNonQuery(const std::string& sql) const;

  // Returns true if the connection is open.
  bool IsConnected() const;

  // Returns column names from the last ExecuteSelect call.
  // Useful for PII classification of actual result sets.
  const std::vector<std::string>& LastColumnNames() const;

 private:
  std::string connection_string_;
  mutable std::vector<std::string> last_column_names_;
};