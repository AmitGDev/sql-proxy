#pragma once
#include <optional>
#include <string>
#include <vector>

// ---------------------------------------------------------------
// User
// ---------------------------------------------------------------
struct User {
  std::string name;  // unique, stored uppercase
  std::string role;  // e.g. "analyst", "admin", "readonly"
};

// ---------------------------------------------------------------
// UserManager
// Loads users from users.json.
// Validates that a requesting user exists before policy evaluation.
// ---------------------------------------------------------------
class UserManager {
 public:
  // Load users from a JSON file. See users.json for format.
  void LoadFromFile(const std::string& path);

  // Add a user programmatically (useful for tests).
  void AddUser(User user);

  // Returns the User if found, empty optional if unknown.
  std::optional<User> FindUser(const std::string& name) const;

  // Returns true if the user exists.
  bool Exists(const std::string& name) const;

  // Dump all loaded users to stdout (debugging helper).
  void PrintUsers() const;

 private:
  std::vector<User> users_;
};