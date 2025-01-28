#ifndef CERT_H
#define CERT_H


#include <array>
#include <gmpxx.h>
#include <istream>
#include <json/value.h>
#include <optional>
#include <string>

std::string get_certificate_core(std::istream &is);
std::optional<Json::Value> pem2json(std::istream &is);

mpz_class str2mpz(std::string &s);

std::optional<std::array<mpz_class, 3>> get_pubkeys(std::istream &is);
std::optional<std::array<mpz_class, 3>> get_pubkeys(Json::Value &value);
std::optional<std::array<mpz_class, 3>> get_keys(std::istream &is);
std::array<mpz_class, 3> get_keys(const Json::Value &value);


#endif
