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

#include <winhttp.h>

#include "https.hpp"

DWORD https_post(
  _In_ PCWSTR domain,
  _In_ PCWSTR url,
  _In_opt_ PCWSTR headers,
  _In_ PCSTR body,
  _Out_ PULONG http_code,
  _Out_opt_ PVOID out_buf,
  _In_ ULONG out_size,
  _Out_ PULONG out_received
) {
  *http_code = 0;

  DWORD ret = ERROR_SUCCESS;
  HINTERNET session{};
  session = WinHttpOpen(
    L"AzuKI/1.0",
    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
    WINHTTP_NO_PROXY_NAME,
    WINHTTP_NO_PROXY_BYPASS,
    0
  );
  if (session) {
    HINTERNET connection{};
    connection = WinHttpConnect(
      session,
      domain,
      INTERNET_DEFAULT_HTTPS_PORT,
      0
    );
    if (connection) {
      HINTERNET request{};
      request = WinHttpOpenRequest(
        connection,
        L"POST",
        url,
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE
      );
      if (request) {
        DWORD body_len = strlen(body);

        BOOL succeeded = FALSE;
        succeeded = WinHttpSendRequest(
          request,
          headers,
          headers ? (DWORD)-1 : 0,
          (LPVOID)body,
          body_len,
          body_len,
          0
        );
        if (succeeded) {
          succeeded = WinHttpReceiveResponse(request, nullptr);
          if (succeeded) {
            DWORD size = sizeof(*http_code);
            succeeded = WinHttpQueryHeaders(
              request,
              WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
              WINHTTP_HEADER_NAME_BY_INDEX,
              http_code,
              &size,
              WINHTTP_NO_HEADER_INDEX
            );
            if (succeeded && out_buf && out_size) {
              succeeded = WinHttpReadData(
                request,
                out_buf,
                out_size,
                out_received
              );
              if (succeeded) {
                (void)0;
              } else {
                ret = GetLastError();
              }
            } else {
              ret = GetLastError();
            }
          } else {
            ret = GetLastError();
          }
        } else {
          ret = GetLastError();
        }
        WinHttpCloseHandle(request);
      } else {
        ret = GetLastError();
      }
      WinHttpCloseHandle(connection);
    } else {
      ret = GetLastError();
    }
    WinHttpCloseHandle(session);
  } else {
    ret = GetLastError();
  }
  return ret;
}
