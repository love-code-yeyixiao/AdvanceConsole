#include<sstream>
#include<istream>
#include<cstring>
#include<iostream>
#include<cstdio>
#include<vector>
#include<objbase.h>
using namespace std;
void StringSplit(std::string str, const char split, std::vector<std::string>& rst)
{
	std::istringstream iss(str);	// 输入流
	std::string token;			// 接收缓冲区
	while (std::getline(iss, token, split))	// 以split为分隔符
	{
		rst.push_back(token);
	}
}
int GetCharNumberOfString(std::string s, std::string c) {
    int index = 0;
    int sum = 0;
    while ((index = s.find(c, index)) != string::npos) {
        index += c.length();
        sum++;
    }
    return sum;
}
char* GuidToString(const GUID guid)
{
	char* buf = (char*)malloc(64);
	snprintf(buf, sizeof(buf),
		"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		guid.Data1, guid.Data2, guid.Data3,
		guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
		guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
	return buf;
}