#include<sstream>
#include<istream>
#include<cstring>
#include<iostream>
#include<cstdio>
#include<vector>
#include<objbase.h>
#include <wincrypt.h>
#include <conio.h>
#include <tchar.h>
#pragma comment (lib, "advapi32")

#define KEYLENGTH  0x00800000
#define ENCRYPT_ALGORITHM CALG_RC4 
#define ENCRYPT_BLOCK_SIZE 8 
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
char buf[64] = { 0 };
char* GuidToString(const GUID guid)
{
	snprintf(buf, sizeof(buf),
		"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		guid.Data1, guid.Data2, guid.Data3,
		guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
		guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
	return buf;
}
void MyHandleError(const char* psz, int nErrorNumber)
{
    printf( "An error occurred in the encryption process. \n");
    printf( "%s\n", psz);
    printf( "Error number %x.\n", nErrorNumber);
}
bool EncryptFileWithMS(
    char* pszSourceFile,
    char* pszDestinationFile,
    char* pszPassword)
{
    //---------------------------------------------------------------
    // Declare and initialize local variables.
    bool fReturn = false;
    HANDLE hSourceFile = INVALID_HANDLE_VALUE;
    HANDLE hDestinationFile = INVALID_HANDLE_VALUE;

    HCRYPTPROV hCryptProv = NULL;
    HCRYPTKEY hKey = NULL;
    HCRYPTKEY hXchgKey = NULL;
    HCRYPTHASH hHash = NULL;

    PBYTE pbKeyBlob = NULL;
    DWORD dwKeyBlobLen;

    PBYTE pbBuffer = NULL;
    DWORD dwBlockLen;
    DWORD dwBufferLen;
    DWORD dwCount;
    bool fEOF = FALSE;


    //---------------------------------------------------------------
    // Open the source file. 
    hSourceFile = CreateFileA(
        pszSourceFile,
        FILE_READ_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (INVALID_HANDLE_VALUE != hSourceFile)
    {
        printf("The source plaintext file, %s, is open. \n",pszSourceFile);
    }
    else
    {
        MyHandleError(
            "Error opening source plaintext file!\n",
            GetLastError());
        goto Exit_MyEncryptFile;
    }

    //---------------------------------------------------------------
    // Open the destination file. 
    hDestinationFile = CreateFileA(
        pszDestinationFile,
        FILE_WRITE_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (INVALID_HANDLE_VALUE != hDestinationFile)
    {
        printf(
            "The destination file, %s, is open. \n",
            pszDestinationFile);
    }
    else
    {
        MyHandleError(
           "Error opening destination file!\n",
            GetLastError());
        goto Exit_MyEncryptFile;
    }

    //---------------------------------------------------------------
    // Get the handle to the default provider. 
    if (CryptAcquireContext(
        &hCryptProv,
        NULL,
        MS_ENHANCED_PROV,
        PROV_RSA_FULL,
        0))
    {
        printf(
            "A cryptographic provider has been acquired. \n");
    }
    else
    {
        MyHandleError(
            "Error during CryptAcquireContext!\n",
            GetLastError());
        goto Exit_MyEncryptFile;
    }

    //---------------------------------------------------------------
    // Create the session key.
    if (!pszPassword || !pszPassword[0])
    {
        //-----------------------------------------------------------
        // No password was passed.
        // Encrypt the file with a random session key, and write the 
        // key to a file. 

        //-----------------------------------------------------------
        // Create a random session key. 
        if (CryptGenKey(
            hCryptProv,
            ENCRYPT_ALGORITHM,
            KEYLENGTH | CRYPT_EXPORTABLE,
            &hKey))
        {
            printf("A session key has been created. \n");
        }
        else
        {
            MyHandleError(
                "Error during CryptGenKey. \n",
                GetLastError());
            goto Exit_MyEncryptFile;
        }

        //-----------------------------------------------------------
        // Get the handle to the exchange public key. 
        if (CryptGetUserKey(
            hCryptProv,
            AT_KEYEXCHANGE,
            &hXchgKey))
        {
            printf(
                "The user public key has been retrieved. \n");
        }
        else
        {
            if (NTE_NO_KEY == GetLastError())
            {
                // No exchange key exists. Try to create one.
                if (!CryptGenKey(
                    hCryptProv,
                    AT_KEYEXCHANGE,
                    CRYPT_EXPORTABLE,
                    &hXchgKey))
                {
                    MyHandleError(
                        "Could not create "
                            "a user public key.\n",
                        GetLastError());
                    goto Exit_MyEncryptFile;
                }
            }
            else
            {
                MyHandleError(
                    "User public key is not available and may "
                    "not exist.\n",
                    GetLastError());
                goto Exit_MyEncryptFile;
            }
        }

        //-----------------------------------------------------------
        // Determine size of the key BLOB, and allocate memory. 
        if (CryptExportKey(
            hKey,
            hXchgKey,
            SIMPLEBLOB,
            0,
            NULL,
            &dwKeyBlobLen))
        {
            printf(
                "The key BLOB is %d bytes long. \n",
                dwKeyBlobLen);
        }
        else
        {
            MyHandleError(
                "Error computing BLOB length! \n",
                GetLastError());
            goto Exit_MyEncryptFile;
        }

        if (pbKeyBlob = (BYTE*)malloc(dwKeyBlobLen))
        {
            printf(
                "Memory is allocated for the key BLOB. \n");
        }
        else
        {
            MyHandleError("Out of memory. \n", E_OUTOFMEMORY);
            goto Exit_MyEncryptFile;
        }

        //-----------------------------------------------------------
        // Encrypt and export the session key into a simple key 
        // BLOB. 
        if (CryptExportKey(
            hKey,
            hXchgKey,
            SIMPLEBLOB,
            0,
            pbKeyBlob,
            &dwKeyBlobLen))
        {
            printf("The key has been exported. \n");
        }
        else
        {
            MyHandleError(
                "Error during CryptExportKey!\n",
                GetLastError());
            goto Exit_MyEncryptFile;
        }

        //-----------------------------------------------------------
        // Release the key exchange key handle. 
        if (hXchgKey)
        {
            if (!(CryptDestroyKey(hXchgKey)))
            {
                MyHandleError(
                    "Error during CryptDestroyKey.\n",
                    GetLastError());
                goto Exit_MyEncryptFile;
            }

            hXchgKey = 0;
        }

        //-----------------------------------------------------------
        // Write the size of the key BLOB to the destination file. 
        if (!WriteFile(
            hDestinationFile,
            &dwKeyBlobLen,
            sizeof(DWORD),
            &dwCount,
            NULL))
        {
            MyHandleError(
                "Error writing header.\n",
                GetLastError());
            goto Exit_MyEncryptFile;
        }
        else
        {
            printf("A file header has been written. \n");
        }

        //-----------------------------------------------------------
        // Write the key BLOB to the destination file. 
        if (!WriteFile(
            hDestinationFile,
            pbKeyBlob,
            dwKeyBlobLen,
            &dwCount,
            NULL))
        {
            MyHandleError(
                "Error writing header.\n",
                GetLastError());
            goto Exit_MyEncryptFile;
        }
        else
        {
            printf(
                "The key BLOB has been written to the "
                "file. \n");
        }

        // Free memory.
        free(pbKeyBlob);
    }
    else
    {

        //-----------------------------------------------------------
        // The file will be encrypted with a session key derived 
        // from a password.
        // The session key will be recreated when the file is 
        // decrypted only if the password used to create the key is 
        // available. 

        //-----------------------------------------------------------
        // Create a hash object. 
        if (CryptCreateHash(
            hCryptProv,
            CALG_MD5,
            0,
            0,
            &hHash))
        {
            printf("A hash object has been created. \n");
        }
        else
        {
            MyHandleError(
                "Error during CryptCreateHash!\n",
                GetLastError());
            goto Exit_MyEncryptFile;
        }

        //-----------------------------------------------------------
        // Hash the password. 
        if (CryptHashData(
            hHash,
            (BYTE*)pszPassword,
            strlen(pszPassword),
            0))
        {
            printf(
                "The password has been added to the hash. \n");
        }
        else
        {
            MyHandleError(
                "Error during CryptHashData. \n",
                GetLastError());
            goto Exit_MyEncryptFile;
        }

        //-----------------------------------------------------------
        // Derive a session key from the hash object. 
        if (CryptDeriveKey(
            hCryptProv,
            ENCRYPT_ALGORITHM,
            hHash,
            KEYLENGTH,
            &hKey))
        {
            printf(
                "An encryption key is derived from the "
                "password hash. \n");
        }
        else
        {
            MyHandleError(
                "Error during CryptDeriveKey!\n",
                GetLastError());
            goto Exit_MyEncryptFile;
        }
    }

    //---------------------------------------------------------------
    // The session key is now ready. If it is not a key derived from 
    // a  password, the session key encrypted with the private key 
    // has been written to the destination file.

    //---------------------------------------------------------------
    // Determine the number of bytes to encrypt at a time. 
    // This must be a multiple of ENCRYPT_BLOCK_SIZE.
    // ENCRYPT_BLOCK_SIZE is set by a #define statement.
    dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;

    //---------------------------------------------------------------
    // Determine the block size. If a block cipher is used, 
    // it must have room for an extra block. 
    if (ENCRYPT_BLOCK_SIZE > 1)
    {
        dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE;
    }
    else
    {
        dwBufferLen = dwBlockLen;
    }

    //---------------------------------------------------------------
    // Allocate memory. 
    if (pbBuffer = (BYTE*)malloc(dwBufferLen))
    {
        printf(
            "Memory has been allocated for the buffer. \n");
    }
    else
    {
        MyHandleError("Out of memory. \n", E_OUTOFMEMORY);
        goto Exit_MyEncryptFile;
    }

    //---------------------------------------------------------------
    // In a do loop, encrypt the source file, 
    // and write to the source file. 
    do
    {
        //-----------------------------------------------------------
        // Read up to dwBlockLen bytes from the source file. 
        if (!ReadFile(
            hSourceFile,
            pbBuffer,
            dwBlockLen,
            &dwCount,
            NULL))
        {
            MyHandleError(
                "Error reading plaintext!\n",
                GetLastError());
            goto Exit_MyEncryptFile;
        }

        if (dwCount < dwBlockLen)
        {
            fEOF = TRUE;
        }

        //-----------------------------------------------------------
        // Encrypt data. 
        if (!CryptEncrypt(
            hKey,
            NULL,
            fEOF,
            0,
            pbBuffer,
            &dwCount,
            dwBufferLen))
        {
            MyHandleError(
                "Error during CryptEncrypt. \n",
                GetLastError());
            goto Exit_MyEncryptFile;
        }

        //-----------------------------------------------------------
        // Write the encrypted data to the destination file. 
        if (!WriteFile(
            hDestinationFile,
            pbBuffer,
            dwCount,
            &dwCount,
            NULL))
        {
            MyHandleError(
                "Error writing ciphertext.\n",
                GetLastError());
            goto Exit_MyEncryptFile;
        }

        //-----------------------------------------------------------
        // End the do loop when the last block of the source file 
        // has been read, encrypted, and written to the destination 
        // file.
    } while (!fEOF);

    fReturn = true;

Exit_MyEncryptFile:
    //---------------------------------------------------------------
    // Close files.
    if (hSourceFile)
    {
        CloseHandle(hSourceFile);
    }

    if (hDestinationFile)
    {
        CloseHandle(hDestinationFile);
    }

    //---------------------------------------------------------------
    // Free memory. 
    if (pbBuffer)
    {
        free(pbBuffer);
    }


    //-----------------------------------------------------------
    // Release the hash object. 
    if (hHash)
    {
        if (!(CryptDestroyHash(hHash)))
        {
            MyHandleError(
                "Error during CryptDestroyHash.\n",
                GetLastError());
        }

        hHash = NULL;
    }

    //---------------------------------------------------------------
    // Release the session key. 
    if (hKey)
    {
        if (!(CryptDestroyKey(hKey)))
        {
            MyHandleError(
                "Error during CryptDestroyKey!\n",
                GetLastError());
        }
    }

    //---------------------------------------------------------------
    // Release the provider handle. 
    if (hCryptProv)
    {
        if (!(CryptReleaseContext(hCryptProv, 0)))
        {
            MyHandleError(
                "Error during CryptReleaseContext!\n",
                GetLastError());
        }
    }

    return fReturn;
}

bool DecryptFileWithMS(
    LPSTR pszSourceFile,
    LPSTR pszDestinationFile,
    LPSTR pszPassword)
{
    //---------------------------------------------------------------
    // Declare and initialize local variables.
    bool fEOF = false;
    bool fReturn = false;
    HANDLE hSourceFile = INVALID_HANDLE_VALUE;
    HANDLE hDestinationFile = INVALID_HANDLE_VALUE;
    HCRYPTKEY hKey = NULL;
    HCRYPTHASH hHash = NULL;

    HCRYPTPROV hCryptProv = NULL;

    DWORD dwCount;
    PBYTE pbBuffer = NULL;
    DWORD dwBlockLen;
    DWORD dwBufferLen;

    //---------------------------------------------------------------
    // Open the source file. 
    hSourceFile = CreateFileA(
        pszSourceFile,
        FILE_READ_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (INVALID_HANDLE_VALUE != hSourceFile)
    {
        printf(
            "The source encrypted file, %s, is open. \n",
            pszSourceFile);
    }
    else
    {
        MyHandleError(
            "Error opening source plaintext file!\n",
            GetLastError());
        goto Exit_MyDecryptFile;
    }

    //---------------------------------------------------------------
    // Open the destination file. 
    hDestinationFile = CreateFileA(
        pszDestinationFile,
        FILE_WRITE_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (INVALID_HANDLE_VALUE != hDestinationFile)
    {
        printf(
            "The destination file, %s, is open. \n",
            pszDestinationFile);
    }
    else
    {
        MyHandleError(
            "Error opening destination file!\n",
            GetLastError());
        goto Exit_MyDecryptFile;
    }

    //---------------------------------------------------------------
    // Get the handle to the default provider. 
    if (CryptAcquireContext(
        &hCryptProv,
        NULL,
        MS_ENHANCED_PROV,
        PROV_RSA_FULL,
        0))
    {
        _tprintf(
            TEXT("A cryptographic provider has been acquired. \n"));
    }
    else
    {
        MyHandleError(
            "Error during CryptAcquireContext!\n",
            GetLastError());
        goto Exit_MyDecryptFile;
    }

    //---------------------------------------------------------------
    // Create the session key.
    if (!pszPassword || !pszPassword[0])
    {
        //-----------------------------------------------------------
        // Decrypt the file with the saved session key. 

        DWORD dwKeyBlobLen;
        PBYTE pbKeyBlob = NULL;

        // Read the key BLOB length from the source file. 
        if (!ReadFile(
            hSourceFile,
            &dwKeyBlobLen,
            sizeof(DWORD),
            &dwCount,
            NULL))
        {
            MyHandleError(
                "Error reading key BLOB length!\n",
                GetLastError());
            goto Exit_MyDecryptFile;
        }

        // Allocate a buffer for the key BLOB.
        if (!(pbKeyBlob = (PBYTE)malloc(dwKeyBlobLen)))
        {
            MyHandleError(
                "Memory allocation error.\n",
                E_OUTOFMEMORY);
        }

        //-----------------------------------------------------------
        // Read the key BLOB from the source file. 
        if (!ReadFile(
            hSourceFile,
            pbKeyBlob,
            dwKeyBlobLen,
            &dwCount,
            NULL))
        {
            MyHandleError(
                "Error reading key BLOB length!\n",
                GetLastError());
            goto Exit_MyDecryptFile;
        }

        //-----------------------------------------------------------
        // Import the key BLOB into the CSP. 
        if (!CryptImportKey(
            hCryptProv,
            pbKeyBlob,
            dwKeyBlobLen,
            0,
            0,
            &hKey))
        {
            MyHandleError(
                "Error during CryptImportKey!/n",
                GetLastError());
            goto Exit_MyDecryptFile;
        }

        if (pbKeyBlob)
        {
            free(pbKeyBlob);
        }
    }
    else
    {
        //-----------------------------------------------------------
        // Decrypt the file with a session key derived from a 
        // password. 

        //-----------------------------------------------------------
        // Create a hash object. 
        if (!CryptCreateHash(
            hCryptProv,
            CALG_MD5,
            0,
            0,
            &hHash))
        {
            MyHandleError(
                "Error during CryptCreateHash!\n",
                GetLastError());
            goto Exit_MyDecryptFile;
        }

        //-----------------------------------------------------------
        // Hash in the password data. 
        if (!CryptHashData(
            hHash,
            (BYTE*)pszPassword,
            strlen(pszPassword),
            0))
        {
            MyHandleError(
                "Error during CryptHashData!\n",
                GetLastError());
            goto Exit_MyDecryptFile;
        }

        //-----------------------------------------------------------
        // Derive a session key from the hash object. 
        if (!CryptDeriveKey(
            hCryptProv,
            ENCRYPT_ALGORITHM,
            hHash,
            KEYLENGTH,
            &hKey))
        {
            MyHandleError(
                "Error during CryptDeriveKey!\n",
                GetLastError());
            goto Exit_MyDecryptFile;
        }
    }

    //---------------------------------------------------------------
    // The decryption key is now available, either having been 
    // imported from a BLOB read in from the source file or having 
    // been created by using the password. This point in the program 
    // is not reached if the decryption key is not available.

    //---------------------------------------------------------------
    // Determine the number of bytes to decrypt at a time. 
    // This must be a multiple of ENCRYPT_BLOCK_SIZE. 

    dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;
    dwBufferLen = dwBlockLen;

    //---------------------------------------------------------------
    // Allocate memory for the file read buffer. 
    if (!(pbBuffer = (PBYTE)malloc(dwBufferLen)))
    {
        MyHandleError("Out of memory!\n", E_OUTOFMEMORY);
        goto Exit_MyDecryptFile;
    }

    //---------------------------------------------------------------
    // Decrypt the source file, and write to the destination file. 
    do
    {
        //-----------------------------------------------------------
        // Read up to dwBlockLen bytes from the source file. 
        if (!ReadFile(
            hSourceFile,
            pbBuffer,
            dwBlockLen,
            &dwCount,
            NULL))
        {
            MyHandleError(
                "Error reading from source file!\n",
                GetLastError());
            goto Exit_MyDecryptFile;
        }

        if (dwCount < dwBlockLen)
        {
            fEOF = TRUE;
        }

        //-----------------------------------------------------------
        // Decrypt the block of data. 
        if (!CryptDecrypt(
            hKey,
            0,
            fEOF,
            0,
            pbBuffer,
            &dwCount))
        {
            MyHandleError(
                "Error during CryptDecrypt!\n",
                GetLastError());
            goto Exit_MyDecryptFile;
        }

        //-----------------------------------------------------------
        // Write the decrypted data to the destination file. 
        if (!WriteFile(
            hDestinationFile,
            pbBuffer,
            dwCount,
            &dwCount,
            NULL))
        {
            MyHandleError(
                "Error writing ciphertext.\n",
                GetLastError());
            goto Exit_MyDecryptFile;
        }

        //-----------------------------------------------------------
        // End the do loop when the last block of the source file 
        // has been read, encrypted, and written to the destination 
        // file.
    } while (!fEOF);

    fReturn = true;

Exit_MyDecryptFile:

    //---------------------------------------------------------------
    // Free the file read buffer.
    if (pbBuffer)
    {
        free(pbBuffer);
    }

    //---------------------------------------------------------------
    // Close files.
    if (hSourceFile)
    {
        CloseHandle(hSourceFile);
    }

    if (hDestinationFile)
    {
        CloseHandle(hDestinationFile);
    }

    //-----------------------------------------------------------
    // Release the hash object. 
    if (hHash)
    {
        if (!(CryptDestroyHash(hHash)))
        {
            MyHandleError(
                "Error during CryptDestroyHash.\n",
                GetLastError());
        }

        hHash = NULL;
    }

    //---------------------------------------------------------------
    // Release the session key. 
    if (hKey)
    {
        if (!(CryptDestroyKey(hKey)))
        {
            MyHandleError(
                "Error during CryptDestroyKey!\n",
                GetLastError());
        }
    }

    //---------------------------------------------------------------
    // Release the provider handle. 
    if (hCryptProv)
    {
        if (!(CryptReleaseContext(hCryptProv, 0)))
        {
            MyHandleError(
                "Error during CryptReleaseContext!\n",
                GetLastError());
        }
    }

    return fReturn;
}

#define BUFSIZE 1024
#define MD5LEN  16
BOOL GetFileHASH(LPCSTR filename,ALG_ID algid)
{
    DWORD dwStatus = 0;
    BOOL bResult = FALSE;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = NULL;
    BYTE rgbFile[BUFSIZE];
    DWORD cbRead = 0;
    BYTE rgbHash[MD5LEN];
    DWORD cbHash = 0;
    CHAR rgbDigits[] = "0123456789abcdef";
   // LPCWSTR filename = L"filename.txt";
    // Logic to check usage goes here.

    hFile = CreateFileA(filename,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        NULL);

    if (INVALID_HANDLE_VALUE == hFile)
    {
        dwStatus = GetLastError();
        printf("Error opening file %s\nError: %d\n", filename,
            dwStatus);
        return dwStatus;
    }

    // Get handle to the crypto provider
    if (!CryptAcquireContext(&hProv,
        NULL,
        NULL,
        PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT))
    {
        dwStatus = GetLastError();
        printf("CryptAcquireContext failed: %d\n", dwStatus);
        CloseHandle(hFile);
        return dwStatus;
    }

    if (!CryptCreateHash(hProv, algid/*CALG_MD5*/, 0, 0, &hHash))
    {
        dwStatus = GetLastError();
        printf("CryptAcquireContext failed: %d\n", dwStatus);
        CloseHandle(hFile);
        CryptReleaseContext(hProv, 0);
        return dwStatus;
    }

    while (bResult = ReadFile(hFile, rgbFile, BUFSIZE,
        &cbRead, NULL))
    {
        if (0 == cbRead)
        {
            break;
        }

        if (!CryptHashData(hHash, rgbFile, cbRead, 0))
        {
            dwStatus = GetLastError();
            printf("CryptHashData failed: %d\n", dwStatus);
            CryptReleaseContext(hProv, 0);
            CryptDestroyHash(hHash);
            CloseHandle(hFile);
            return dwStatus;
        }
    }

    if (!bResult)
    {
        dwStatus = GetLastError();
        printf("ReadFile failed: %d\n", dwStatus);
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CloseHandle(hFile);
        return dwStatus;
    }

    cbHash = MD5LEN;
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
        printf("Hash of file %s is: ", filename);
        for (DWORD i = 0; i < cbHash; i++)
        {
            printf("%c%c", rgbDigits[rgbHash[i] >> 4],
                rgbDigits[rgbHash[i] & 0xf]);
        }
        printf("\n");
    }
    else
    {
        dwStatus = GetLastError();
        printf("CryptGetHashParam failed: %d\n", dwStatus);
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);

    return dwStatus;
}