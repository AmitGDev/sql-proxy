// Header corresponding to the.cpp file
#include "DbExecutor.hpp"

// Standard library headers
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

// Standard library headers
#include <pqxx/pqxx>

// ---------------------------------------------------------------
// DbExecutor
// ---------------------------------------------------------------
DbExecutor::DbExecutor(const std::string& connection_string)
    : connection_string_(connection_string) {
  // Eagerly validate the connection string on construction.
  // (Pros: Fails fast if the config is wrong. Cons: Delayed startup)
  // Throws pqxx::broken_connection if the DB is unreachable.
  const pqxx::connection conn(connection_string_);
  if (!conn.is_open()) {
    throw std::runtime_error(
        "DbExecutor: failed to open connection to database.");
  }
}

// ---------------------------------------------------------------
// ExecuteSelect
// Opens a read-only transaction, runs the query, returns all
// rows as vectors of strings.  Also captures column names for
// downstream PII classification.
// ---------------------------------------------------------------
QueryResult DbExecutor::ExecuteSelect(const std::string& sql) const {
  pqxx::connection conn(connection_string_);
  pqxx::nontransaction transaction(conn);  // read-only, no commit needed

  const pqxx::result res = transaction.exec(sql);

  // Capture column names
  last_column_names_.clear();
  for (int column_index = 0; column_index < static_cast<int>(res.columns());
       ++column_index) {
    last_column_names_.push_back(res.column_name(column_index));
  }

  // Collect rows
  QueryResult rows;
  rows.reserve(res.size());
  for (const auto& row : res) {
    QueryRow query_row;
    query_row.reserve(row.size());
    for (const auto& field : row) {
      query_row.push_back(field.is_null() ? "NULL" : field.c_str());
    }
    rows.push_back(std::move(query_row));
  }

  return rows;
}

// ---------------------------------------------------------------
// ExecuteNonQuery
// Runs DDL or DML inside a transaction and commits.
// Returns affected row count (0 for DDL).
// ---------------------------------------------------------------
int DbExecutor::ExecuteNonQuery(const std::string& sql) const {
  pqxx::connection conn(connection_string_);
  pqxx::work transaction(conn);

  const pqxx::result res = transaction.exec(sql);
  transaction.commit();

  return static_cast<int>(res.affected_rows());
}

// ---------------------------------------------------------------
// IsConnected
// ---------------------------------------------------------------
bool DbExecutor::IsConnected() const {
  try {
    pqxx::connection conn(connection_string_);
    return conn.is_open();
  } catch (...) {
    return false;
  }
}

// ---------------------------------------------------------------
// LastColumnNames
// ---------------------------------------------------------------
const std::vector<std::string>& DbExecutor::LastColumnNames() const {
  return last_column_names_;
}