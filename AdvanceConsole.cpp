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
        *cszNoArgu="No command arguments.",* cszCopyright="Copyright Love-Code-Yeyixiao",*cszLicense="You are now not allowed to recompile, use or distribute the application after modifying the source code.";

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
    cout << cszCopyright << endl  <<  cszLicense << endl;
    return TRUE;
}
BOOL init() {
    BOOL status = TRUE;
    status=initOutput();
    SetConsoleTitleA("Advance Console 0.0.1 Working Version");
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
        if (_strcmpi("EncryptWithMS", vctCmd[0].c_str()) == 0) {
            isPraseSuccess = TRUE;
            if (vctCmd.size() != 4) {
                isPraseSuccess = FALSE;
                ErrorTip(1000);
            }
            else {
                char Sourcepath[256] = { 0 }, Targetpath[256] = { 0 }, password[600] = {0};
                strcpy_s(Sourcepath, vctCmd[1].c_str());
                strcpy_s(Targetpath, vctCmd[2].c_str());
                strcpy_s(password, vctCmd[3].c_str());
                BOOL isSucced = EncryptFileWithMS(Sourcepath, Targetpath, password);
                cout<<isSucced?"Encryption Successfully!": "Encryption Failed!";
            }
            continue;
        }
         if (_strcmpi("DecryptWithMS", vctCmd[0].c_str()) == 0) {
                isPraseSuccess = TRUE;
                if (vctCmd.size() != 4) {
                    isPraseSuccess = FALSE;
                    ErrorTip(1000);
                }
                else {
                    char Sourcepath[256] = { 0 }, Targetpath[256] = { 0 }, password[600] = { 0 };
                    strcpy_s(Sourcepath, vctCmd[1].c_str());
                    strcpy_s(Targetpath, vctCmd[2].c_str());
                    strcpy_s(password, vctCmd[3].c_str());
                    BOOL isSucced = DecryptFileWithMS(Sourcepath, Targetpath, password);
                    cout << isSucced ? "Encryption Successfully!" : "Encryption Failed!";
                }
                continue;
         }
        else if (_strcmpi("sumGUID", inputBuf) == 0) {
             isPraseSuccess = TRUE;
            GUID guid;
            if (CoCreateGuid(&guid) == S_OK) {
                char* guidBuf = GuidToString(guid);
                cout << guidBuf << endl;
            }
            else {
                cout << "Failed to generate Guid!" << endl;
            }
            continue;
        }
         if (_strcmpi("GetFileMD5", vctCmd[0].c_str()) == 0) {
             isPraseSuccess = TRUE;
             if (vctCmd.size() != 2) {
                 isPraseSuccess = FALSE;
                 ErrorTip(1000);
             }
             else {
                 if (!GetFileHASH(vctCmd[1].c_str(), CALG_MD5)) {
                     cout << "Failed to get hash!" << endl;
                 }
             }
             continue;
         }
         if (_strcmpi("GetFileSHA", vctCmd[0].c_str()) == 0) {
             isPraseSuccess = TRUE;
             if (vctCmd.size() != 2) {
                 isPraseSuccess = FALSE;
                 ErrorTip(1000);
             }
             else {
                 if (!GetFileHASH(vctCmd[1].c_str(), CALG_SHA1)) {
                     cout << "Failed to get hash!" << endl;
                 }
             }
             continue;
         }
         if (_strcmpi("GetFileSHA256", vctCmd[0].c_str()) == 0) {
             isPraseSuccess = TRUE;
             if (vctCmd.size() != 2) {
                 isPraseSuccess = FALSE;
                 ErrorTip(1000);
             }
             else {
                 if (!GetFileHASH(vctCmd[1].c_str(), CALG_SHA_256)) {
                     cout << "Failed to get hash!" << endl;
                 }
             }
             continue;
         }
         if (_strcmpi("GetFileSHA512", vctCmd[0].c_str()) == 0) {
             isPraseSuccess = TRUE;
             if (vctCmd.size() != 2) {
                 isPraseSuccess = FALSE;
                 ErrorTip(1000);
             }
             else {
                 if (!GetFileHASH(vctCmd[1].c_str(), CALG_SHA_512)) {
                     cout << "Failed to get hash!" << endl;
                 }
             }
             continue;
         }
        else if (_strcmpi("exit", inputBuf) == 0) {
            cout << "Press Enter to exit AdvanceConsole";
            cin.getline(inputBuf, 0);
            exit(0);
        }
        else if (_strcmpi("ForceExit", inputBuf) == 0) {
            CloseWindow(GetConsoleWindow());
            DestroyWindow(GetConsoleWindow());
            PostQuitMessage(0);
            TerminateProcess(GetCurrentProcess(), 0);
            TerminateThread(GetCurrentThread(), 0);
            ExitProcess(0);
            ExitThread(0);
            exit(0);
        }
        else if (_strcmpi("KillFocusWindow", inputBuf) == 0)
        {
            cout << "Wait 3 seconds";
            Sleep(1000);
            cout << ".";
            Sleep(1000);
            cout << ".";
            Sleep(1000);
            cout << "." << endl;
            HWND hWnd = GetForegroundWindow();
            CloseWindow(hWnd);
            Sleep(2000);
            DestroyWindow(IsWindow(hWnd)?hWnd:NULL);
            SendMessage(hWnd, WM_CLOSE, NULL, NULL);
            continue;
        }
        else if (_strcmpi("KillFocusWindowForce", inputBuf) == 0)
        {
            cout << "Wait 3 seconds";
            Sleep(1000);
            cout << ".";
            Sleep(1000);
            cout << ".";
            Sleep(1000);
            cout << "." << endl;
            HWND hWnd = GetForegroundWindow();
            ULONG pid = 0;
            GetWindowThreadProcessId(hWnd, &pid);
            CloseWindow(hWnd);
            Sleep(2000);
            DestroyWindow(IsWindow(hWnd) ? hWnd : NULL);
            SendMessage(hWnd, WM_CLOSE, NULL, NULL);
            PostMessage(hWnd, WM_QUIT, NULL, NULL);
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
            if (hProcess != NULL && hProcess != INVALID_HANDLE_VALUE) {
                TerminateProcess(hProcess, 0);
            }
            else {
                cout << "Target could be killed by normal ways or can't be terminated!" << endl;
            }
            continue;
        }
        else if (_strcmpi("KillCursorWindow", inputBuf) == 0)
        {
            cout << "Wait 3 seconds";
            Sleep(1000);
            cout << ".";
            Sleep(1000);
            cout << ".";
            Sleep(1000);
            cout << "." << endl;
            POINT poi;
            GetCursorPos(&poi);
            HWND hWnd = WindowFromPoint(poi);
            CloseWindow(hWnd);
            Sleep(2000);
            DestroyWindow(IsWindow(hWnd) ? hWnd : NULL);
            SendMessage(hWnd, WM_CLOSE, NULL, NULL);
            continue;
        }
        else if (_strcmpi("KillCursorWindowForce", inputBuf) == 0)
        {
            cout << "Wait 3 seconds";
            Sleep(1000);
            cout << ".";
            Sleep(1000);
            cout << ".";
            Sleep(1000);
            cout << "." << endl;
            POINT poi;
            GetCursorPos(&poi);
            HWND hWnd = WindowFromPoint(poi);
            ULONG pid = 0;
            GetWindowThreadProcessId(hWnd, &pid);
            CloseWindow(hWnd);
            Sleep(2000);
            DestroyWindow(IsWindow(hWnd) ? hWnd : NULL);
            SendMessage(hWnd, WM_CLOSE, NULL, NULL);
            PostMessage(hWnd, WM_QUIT, NULL, NULL);
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
            if (hProcess != NULL && hProcess != INVALID_HANDLE_VALUE) {
                TerminateProcess(hProcess, 0);
            }
            else {
                cout << "Target could be killed by normal ways or can't be terminated!" << endl;
            }
            continue;
        }
        else if (_strcmpi("EnableWindow", inputBuf) == 0) {
            cout << "Wait 3 seconds";
            Sleep(1000);
            cout << ".";
            Sleep(1000);
            cout << ".";
            Sleep(1000);
            cout << "." << endl;
            POINT poi;
            GetCursorPos(&poi);
            HWND hParent = WindowFromPoint(poi);
            HWND hChild = ChildWindowFromPoint(hParent, poi);
            EnableWindow(hParent,TRUE);
            continue;
        }
        else if (_strcmpi("DisableWindow", inputBuf) == 0) {
            cout << "Wait 3 seconds";
            Sleep(1000);
            cout << ".";
            Sleep(1000);
            cout << ".";
            Sleep(1000);
            cout << "." << endl;
            POINT poi;
            GetCursorPos(&poi);
            HWND hParent = WindowFromPoint(poi);
            HWND hChild = ChildWindowFromPoint(hParent, poi);
            EnableWindow(hParent, FALSE);
            continue;
            }
        else if (_strcmpi("Lock", inputBuf) == 0) {
            LockWorkStation();
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
