#include <iostream>
#include <pqxx/pqxx>

int ConnectToDbTest() {
  // Establish connection to the database
  pqxx::connection connection(
      "host=localhost port=5432 dbname=testdb user=postgres password=postgres");

  // Execute a transaction on the database
  pqxx::work transaction(connection);
  auto result = transaction.exec("SELECT count(*) FROM customers");

  std::cout << "Customers: " << result[0][0].as<int>() << "\n";
}