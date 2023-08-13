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

#include <Windows.h>

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <xutility>

#include "b64.hpp"
#include "https.hpp"
#include "json.hpp"

template <typename Char>
auto format_string_v(const _In_z_ _Printf_format_string_ Char* fmt, va_list va) -> std::basic_string<Char> {
  using cfn_t = int (*)(const Char*, va_list);
  using fn_t = int (*)(Char*, size_t, const Char*, va_list);
  cfn_t cfn;
  fn_t fn;
  if constexpr (std::is_same_v<Char, char>) {
    cfn = &_vscprintf;
    fn = &vsprintf_s;
  } else {
    cfn = &_vscwprintf;
    fn = &vswprintf_s;
  }

  std::basic_string<Char> str;

  int len = cfn(fmt, va);
  str.resize((size_t)len);
  fn(str.data(), str.size() + 1, fmt, va);

  return str;
}

template <typename Char>
auto format_string(const _In_z_ _Printf_format_string_ Char* fmt, ...) -> std::basic_string<Char> {
  va_list args;
  va_start(args, fmt);
  auto str = format_string_v(fmt, args);
  va_end(args);
  return str;
}

template <typename Char>
static std::basic_string<Char> env(const Char* name) {
  const Char* str;
  if constexpr (std::is_same_v<Char, char>) {
    str = getenv(name);
  } else {
    str = _wgetenv(name);
  }
  return str ? std::basic_string<Char>{str} : std::basic_string<Char>{};
}

const char* get_web_key_signature_algorithm(const char* pszObjId, ALG_ID digestAlgId) {
  if (0 == strcmp(pszObjId, szOID_RSA_SHA256RSA) && digestAlgId == CALG_SHA_256)
    return "RS256";
  else if (0 == strcmp(pszObjId, szOID_RSA_SHA384RSA) && digestAlgId == CALG_SHA_384)
    return "RS384";
  else if (0 == strcmp(pszObjId, szOID_RSA_SHA512RSA) && digestAlgId == CALG_SHA_512)
    return "RS512";
  else if (0 == strcmp(pszObjId, szOID_ECC_CURVE_P256) && digestAlgId == CALG_SHA_256)
    return "ES256";
  else if (0 == strcmp(pszObjId, szOID_ECC_CURVE_P384) && digestAlgId == CALG_SHA_384)
    return "ES384";
  else if (0 == strcmp(pszObjId, szOID_ECC_CURVE_P521) && digestAlgId == CALG_SHA_512)
    return "ES512";
  return nullptr;
}

static std::string urlencode(const char* in) {
  static const char s_hex[] = "0123456789ABCDEF";
  std::string out{};
  while (*in) {
    auto c = *in++;
    if (isalnum(c))
      out.push_back(c);
    else {
      out.push_back('%');
      out.push_back(s_hex[(unsigned)c >> 4]);
      out.push_back(s_hex[(unsigned)c & 0xF]);
    }
  }
  return out;
}

static HRESULT get_token(std::string& token) {
  token = env("AZUKI_TOKEN");
  if (!token.empty()) {
    return S_OK;
  }
  auto login = env(L"AZUKI_LOGIN_HOST");
  if (login.empty())
    login = L"login.microsoftonline.com";
  auto resource = env("AZUKI_RESOURCE");
  if (resource.empty())
    resource = "https://vault.azure.net";
  const auto client_id = env("AZUKI_CLIENT_ID");
  const auto client_secret = env("AZUKI_CLIENT_SECRET");
  const auto tenant_id = env(L"AZUKI_TENANT_ID");
  if (client_id.empty() || client_secret.empty() || tenant_id.empty()) {
    printf("Invalid or missing environment variables!\n");
    return HRESULT_FROM_WIN32(ERROR_INVALID_ENVIRONMENT);
  }

  const auto url = format_string(L"/%s/oauth2/token", tenant_id.c_str());
  const auto body = format_string(
    "grant_type=client_credentials&client_id=%s&client_secret=%s&resource=%s",
    urlencode(client_id.c_str()).c_str(),
    urlencode(client_secret.c_str()).c_str(),
    urlencode(resource.c_str()).c_str()
  );

  char response[4096]{};
  ULONG received{};
  ULONG http_code{};
  const auto err = https_post(
    login.c_str(),
    url.c_str(),
    L"Content-Type: application/x-www-form-urlencoded",
    body.c_str(),
    &http_code,
    response,
    sizeof(response) - 1,
    &received
  );
  if (err) {
    printf("HTTPS request for getting token failed with code %lu.\n", err);
    return HRESULT_FROM_WIN32(err);
  }
  response[received] = 0;
  if (!http_code) {
    printf("HTTPS request for getting token resulted in invalid HTTP code.\n");
    return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
  }
  if (http_code < 200 || http_code >= 300) {
    printf("HTTPS request for getting token resulted in HTTP code %lu. Response body: %s\n", http_code, response);
    return E_FAIL;
  }

  json_parser j{response};

  const auto prop = json_getProperty(j.root(), "access_token");
  const auto value = json_getValue(prop);

  token = value;

  return S_OK;
}

extern "C" __declspec(dllexport) HRESULT WINAPI AuthenticodeDigestSign(
  _In_ PCCERT_CONTEXT pSigningCert,
  _In_opt_ PCRYPT_DATA_BLOB,
  _In_ ALG_ID digestAlgId,
  _In_ PBYTE pbToBeSignedDigest,
  _In_ DWORD cbToBeSignedDigest,
  _Out_ PCRYPT_DATA_BLOB pSignedDigest
) {
  std::string body;
  {
    const auto pszObjId = pSigningCert->pCertInfo->SignatureAlgorithm.pszObjId;
    const auto alg = get_web_key_signature_algorithm(pszObjId, digestAlgId);
    if (!alg) {
      printf("Algorithm not supported. pszObjId: %s digestAlgId: %X\n", pszObjId, digestAlgId);
      return E_INVALIDARG;
    }
    body = format_string(
      R"({"alg":"%s","value":"%s"})",
      alg,
      b64::encode(pbToBeSignedDigest, cbToBeSignedDigest).c_str()
    );
  }

  const auto domain = env(L"AZUKI_VAULT_DOMAIN");
  const auto key = env(L"AZUKI_KEY_NAME");
  if (domain.empty() || key.empty()) {
    printf("Invalid or missing environment variables!\n");
    return HRESULT_FROM_WIN32(ERROR_INVALID_ENVIRONMENT);
  }

  std::string token{};
  auto result = get_token(token);
  if (FAILED(result)) {
    printf("Getting token failed: %lX", result);
    return result;
  }

  const auto url = format_string(L"/keys/%s/sign?api-version=7.4", key.c_str());
  const auto headers = format_string(L"Content-Type: application/json\r\nAuthorization: Bearer %hs\r\n", token.c_str());

  ULONG http_code{};
  char response[4096]{};
  ULONG received{};
  auto err = https_post(
    domain.c_str(),
    url.c_str(),
    headers.c_str(),
    body.c_str(),
    &http_code,
    response,
    sizeof(response) - 1,
    &received
  );
  if (err) {
    printf("HTTPS request failed with code %lu.\n", err);
    return HRESULT_FROM_WIN32(err);
  }
  response[received] = 0;
  if (!http_code) {
    printf("HTTPS request resulted in invalid HTTP code.\n");
    return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
  }
  if (http_code < 200 || http_code >= 300) {
    printf("HTTPS request resulted in HTTP code %lu. Response body: %s\n", http_code, response);
    return E_FAIL;
  }

  json_parser jp{response};
  const auto prop = json_getProperty(jp.root(), "value");
  const auto value = (char*)json_getValue(prop);
  const auto value_len = strlen(value);

  for (size_t i = 0; i < value_len; ++i) {
    if (value[i] == '-')
      value[i] = '+';
    if (value[i] == '_')
      value[i] = '/';
  }

  const auto decoded = b64::decode(value);
  const auto decoded_size = decoded.size();

  const auto sig_buf = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, decoded_size);
  memcpy(sig_buf, decoded.data(), decoded_size);

  pSignedDigest->cbData = decoded_size;
  pSignedDigest->pbData = sig_buf;

  return S_OK;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) {
  return TRUE;
}
