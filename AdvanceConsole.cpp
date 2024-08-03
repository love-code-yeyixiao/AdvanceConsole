// AdvanceConsole.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include<Windows.h>
#include<cstdio>
#include <iostream>
#include<cstring>
#include<vector>
#include<exception>
#include<algorithm>
#include<Objbase.h>

#include "common.h"

using namespace std;

//
//Global Varierables
//
static long globalType = 0;



//
//Initalize Funcation
//
BOOL checkArguments() {
    return FALSE;
}
BOOL initOutput() {
    const CHAR* cszTitle = "Advance Console 0.0.1 Working Version",
        *cszNoArgu="No command arguments.";

    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), BACKGROUND_RED);
    for (int i = 0; i <= 1000; i++)
        printf(" ");
    cout.flush();
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | BACKGROUND_RED);
    system("cls");

    cout << cszTitle << endl;
    BOOL isArgument = checkArguments();
    if (!isArgument) {
        cout << cszNoArgu<<endl;
        globalType = 1;
        return TRUE;
    }
    return TRUE;
}
BOOL init() {
    BOOL status = TRUE;
    status=initOutput();
    return status;
}


//
//DefaultWork
//
vector<string> vctCmd;
BOOL isPraseSuccess = FALSE;
char inputBuf[256] = { 0 };
void LogOutput(ULONG uCode) {

}
void errorGrammar()
{
    cout << "Command usage syntax error!" << endl;
    
}
void errorE2Big() {
    cout << "The list of independent variables is too large"<<endl;
}
void errorNotFound() {
    if (inputBuf!=NULL)
        cout<< "'" << inputBuf << "'" << " is not an internal or external command, nor is it a runnable program or a batch file" << endl;
}
void errorNoCmd() {
    cout << "Can't find system CMD!";
}
void ErrorTip(ULONG uCode) {
    if (uCode == 1000) {
        errorGrammar();
    }
    else if (uCode == 1001) {
        errorNotFound();
    }
    else if (uCode == 1003) {
        errorE2Big();
    }
    else if (uCode == 1004) {
        errorNoCmd();
    }
    LogOutput(uCode);
}
void PraseCDAndExecute() {
    string path = vctCmd[1];
    //if (GetCharNumberOfString(path, ".") == vctCmd[1].length())
    if (SetCurrentDirectoryA(path.c_str()) == 0)
        cout << "Failed to change Current Directory!"<<endl;
    
}
BOOL DefaultWork() {
    BOOL state = TRUE;
    cout << "Welcome to Default State of the application." << endl <<"Input \"ChangeMode n\" to set console mode"<<endl;
    char buf[MAX_PATH+1] = { 0 };
    
    while (TRUE) {
        memset(inputBuf, 0, 256);
        vctCmd.clear();
        GetCurrentDirectoryA(MAX_PATH, buf);
        cout << buf << ">";
        cin.getline(inputBuf, 256);
        StringSplit(inputBuf, ' ', vctCmd);
        if (vctCmd.empty()) {
            continue;
        }
        /*if (_strcmpi("cd", vctCmd[0].c_str()) == 0) {
            isPraseSuccess = TRUE;
            if (vctCmd.size() != 2) {
                isPraseSuccess = FALSE;
                ErrorTip(1000);
            }
            else {
                PraseCDAndExecute();
            }
        }
        else if(_strcmpi(inputBuf,"cls")==0) {
            isPraseSuccess = TRUE;
            system("cls");
        }
        else if (_strcmpi(inputBuf, "dir") == 0) {
            isPraseSuccess = TRUE;
            system("dir");
        }
        else if (_strcmpi(inputBuf, "ver") == 0) {
            isPraseSuccess = TRUE;
            WinExec("winver.exe", SW_SHOW);
        }
        else if (_strcmpi("start", vctCmd[0].c_str()) == 0) {
            isPraseSuccess = TRUE;
            string tmpBuf = inputBuf;
            string tmpBuf2 = "start ";
            transform(tmpBuf.begin(), tmpBuf.end(), tmpBuf.begin(), tolower);
            WinExec(tmpBuf.replace(tmpBuf.find(tmpBuf2), 1, "").data(), SW_SHOW);
        }
        else if (_strcmpi("color", vctCmd[0].c_str()) == 0) {
            isPraseSuccess = TRUE;
            system(inputBuf);
        }*/
        if (_strcmpi("cd", vctCmd[0].c_str()) == 0) {
            isPraseSuccess = TRUE;
            if (vctCmd.size() != 2) {
                isPraseSuccess = FALSE;
                ErrorTip(1000);
            }
            else {
                PraseCDAndExecute();
            }
            continue;
        }
        else if (_strcmpi("sumGUID", inputBuf) == 0) {
            GUID guid;
            if (CoCreateGuid(&guid) == S_OK) {
                char *guidBuf = GuidToString(guid);
                cout << guidBuf<<endl;
                free(guidBuf);
            }
            else {
                cout << "Failed to generate Guid!";
            }
            continue;
        }
        errno = 0;
        int rtn = system(inputBuf);
        if (rtn==-1 && errno==E2BIG) {
            ErrorTip(1003);
        }
#ifdef _DEBUG
        else if (_strcmpi(inputBuf, "crashCmd") == 0) {
            isPraseSuccess = TRUE;
            throw "I crashed the cmd!";
        }
#endif
        else if (rtn == -1 && errno == ENOENT) {
            ErrorTip(1004);
        }
        else if (rtn == -1 && errno == ENOEXEC)
        {
            ErrorTip(1001);
        }
        else if (inputBuf != "" && inputBuf != NULL&&rtn==-1) {
            isPraseSuccess = FALSE;
            ErrorTip(1001);
        }
    }
    return state;
}
int main()
{
    __try {
        init();
        if (globalType == 1)
        {
        repeat:
            __try {
                DefaultWork();
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                cerr << "\nAdvanceConsole DefaultWork Module crashed just now.This is the exception:" << GetExceptionCode();
            }
            cerr << endl << "What choice do you want to do:(1)Restart application in SystemLevel.(2)Restart us in thread level.(3)Exit." << endl << "Input number directly.";
            short i = 0;
            cin >> i;
            switch (i) {
            case 1:
                WinExec(GetCommandLineA(), SW_SHOW);
                exit(0);
                break;
            case 2:
                goto repeat;
                break;
            case 3:
                exit(0);
                break;
            default:
                CloseWindow(GetConsoleWindow());
                TerminateProcess(GetCurrentProcess(), 1314);
                break;
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER){
        cout << "\nAdvanceConsole suffers an unrecoverable crash and will exit automatically after three seconds";
        Sleep(3000);
        ExitProcess(1315);
    }
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
