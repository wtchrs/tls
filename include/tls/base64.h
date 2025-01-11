//
// Created by wtchr on 8/21/2024.
//

#ifndef BASE64_H
#define BASE64_H

#include <string>
#include <vector>

std::string base64_encode(std::vector<unsigned char> v);

std::vector<unsigned char> base64_decode(const std::string &s);

#endif
