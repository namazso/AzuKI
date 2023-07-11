// MIT License
//
// Copyright (c) namazso 2023
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#pragma once

#include <list>
#include <string>

#include "tiny-json/tiny-json.h"

class json_parser : jsonPool_t {
  static json_t* alloc_fn(jsonPool_t* pool) {
    const auto list_pool = static_cast<json_parser*>(pool); // NOLINT(cppcoreguidelines-pro-type-static-cast-downcast)
    return &list_pool->_list.emplace_back();
  }

  std::list<json_t> _list{};
  std::string _str{};
  const json_t* _root{};

public:
  json_parser()
      : jsonPool_t{&alloc_fn, &alloc_fn} {}

  explicit json_parser(const char* str)
      : jsonPool_t{&alloc_fn, &alloc_fn}
      , _str{str} {
    _root = json_createWithPool(_str.data(), this);
  }

  json_parser(const json_parser&) = delete;
  json_parser(json_parser&&) = delete;
  json_parser& operator=(const json_parser&) = delete;
  json_parser& operator=(json_parser&&) = delete;

  void parse(const char* str) {
    _str = str;
    _list.clear();
    _root = json_createWithPool(_str.data(), this);
  }

  [[nodiscard]] const json_t* root() const { return _root; }
};
