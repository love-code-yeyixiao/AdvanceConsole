#include<sstream>
#include<istream>
#include<cstring>
#include<iostream>
#include<cstdio>
#include<vector>
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