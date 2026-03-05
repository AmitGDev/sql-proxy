#include "UserManager.hpp"

#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <stdexcept>

#include "Utility.hpp"

// ---------------------------------------------------------------
// LoadFromFile
//
// Expected JSON format:
// {
//   "users": [
//     { "name": "alice", "role": "analyst"  },
//     { "name": "bob",   "role": "readonly" },
//     { "name": "admin", "role": "admin"    }
//   ]
// }
// ---------------------------------------------------------------
void UserManager::LoadFromFile(const std::string& path) {
  std::ifstream file(path);
  if (!file.is_open()) {
    throw std::runtime_error("Cannot open users file: " + path);
  }

  nlohmann::json json;
  file >> json;

  for (const auto& item : json.at("users")) {
    User u;
    u.name = ToUpper(item.at("name").get<std::string>());
    u.role = item.at("role").get<std::string>();
    users_.push_back(std::move(u));
  }
}

// ---------------------------------------------------------------
// AddUser
// ---------------------------------------------------------------
void UserManager::AddUser(User user) {
  user.name = ToUpper(user.name);
  users_.push_back(std::move(user));
}

// ---------------------------------------------------------------
// FindUser
// ---------------------------------------------------------------
std::optional<User> UserManager::FindUser(const std::string& name) const {
  const std::string upper = ToUpper(name);
  for (const auto& u : users_) {
    if (u.name == upper) {
      return u;
    }
  }
  return std::nullopt;
}

// ---------------------------------------------------------------
// Exists
// ---------------------------------------------------------------
bool UserManager::Exists(const std::string& name) const {
  return FindUser(name).has_value();
}

// ---------------------------------------------------------------
// PrintUsers
// ---------------------------------------------------------------
void UserManager::PrintUsers() const {
  std::cout << "=== Loaded Users ===\n";
  for (const auto& u : users_) {
    std::cout << "  name=" << u.name << "  role=" << u.role << "\n";
  }
  std::cout << "====================\n\n";
}