#include<sstream>
#include<istream>
#include<cstring>
#include<iostream>
#include<cstdio>
#include<vector>
using namespace std;
void StringSplit(std::string str, const char split, std::vector<std::string>& rst)
{
	std::istringstream iss(str);	// ������
	std::string token;			// ���ջ�����
	while (std::getline(iss, token, split))	// ��splitΪ�ָ���
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