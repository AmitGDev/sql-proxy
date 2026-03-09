// Utility.cpp

#include <cctype>
#include <ranges>
#include <string>
#include <string_view>

std::string ToUpper(std::string_view str) {
  return str | std::views::transform([](unsigned char c) {
           return std::toupper(c);
         }) |
         std::ranges::to<std::string>();
}