#pragma once

void StringSplit(std::string str, const char split, std::vector<std::string>& rst);
int GetCharNumberOfString(std::string s, std::string c);
char* GuidToString(const GUID guid);
bool EncryptFileWithMS(
    char* pszSourceFile,
    char* pszDestinationFile,
    char* pszPassword);
bool DecryptFileWithMS(
    LPSTR pszSourceFile,
    LPSTR pszDestinationFile,
    LPSTR pszPassword);
BOOL GetFileHASH(LPCSTR filename, ALG_ID algid, DWORD bufferLength, const WCHAR* Provider);
unsigned char* acl_base64_encode(const char* in, int len);
unsigned char* acl_base64_decode(const char* in, int len);
