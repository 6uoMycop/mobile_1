#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h> 
#include <initguid.h> 
#include <winsock2.h> 
#include <ws2bth.h> 
#include <strsafe.h> 
#include <intsafe.h>
#include <thread>
#include <wchar.h>
#include <mutex>

#pragma comment(lib, "ws2_32.lib")

DEFINE_GUID(g_guidServiceClass, 0xb62c4e8d, 0x62cc, 0x404b, 0xbb, 0xbf, 0xbf, 0x3e, 0x3b, 0xbb, 0x13, 0x73);


#define CXN_BDADDR_STR_LEN                17   // 6 two-digit hex values plus 5 colons 
#define CXN_MAX_INQUIRY_RETRY             3 
#define CXN_DELAY_NEXT_INQUIRY            2 
#define CXN_SUCCESS                       0 
#define CXN_ERROR                         1 
#define CXN_DEFAULT_LISTEN_BACKLOG        4 

int gHeight                               = 1080;
int gWidth                                = 1920;
wchar_t g_szMyName[BTH_MAX_NAME_SIZE + 1];

wchar_t g_szRemoteName[BTH_MAX_NAME_SIZE + 1] = { 0 };  // 1 extra for trailing NULL character 
wchar_t g_szRemoteAddr[CXN_BDADDR_STR_LEN + 1] = { 0 }; // 1 extra for trailing NULL character 
char g_szPath[512] = { 0 };
int  g_ulMaxCxnCycles = 1;

std::mutex outputMut;

ULONG NameToBthAddr(_In_ const LPWSTR pszRemoteName, _Out_ PSOCKADDR_BTH pRemoteBthAddr);
ULONG RunClientMode(_In_ SOCKADDR_BTH ululRemoteBthAddr, _In_ int iMaxCxnCycles, _In_ int mode, _In_ char* filePathToSend = NULL);
ULONG RunServerMode(_In_ int iMaxCxnCycles = 1);


PBITMAPINFO CreateBitmapInfoStruct(HBITMAP hBmp)
{
    BITMAP bmp;
    PBITMAPINFO pbmi;
    WORD    cClrBits;

    // Retrieve the bitmap color format, width, and height.  
    GetObjectA(hBmp, sizeof(BITMAP), (LPSTR)&bmp);

    // Convert the color format to a count of bits.  
    cClrBits = (WORD)(bmp.bmPlanes * bmp.bmBitsPixel);
    if (cClrBits == 1)
        cClrBits = 1;
    else if (cClrBits <= 4)
        cClrBits = 4;
    else if (cClrBits <= 8)
        cClrBits = 8;
    else if (cClrBits <= 16)
        cClrBits = 16;
    else if (cClrBits <= 24)
        cClrBits = 24;
    else cClrBits = 32;

    // Allocate memory for the BITMAPINFO structure. (This structure  
    // contains a BITMAPINFOHEADER structure and an array of RGBQUAD  
    // data structures.)  

    if (cClrBits < 24)
        pbmi = (PBITMAPINFO)LocalAlloc(LPTR,
            sizeof(BITMAPINFOHEADER) +
            sizeof(RGBQUAD) * (1 << cClrBits));

    // There is no RGBQUAD array for these formats: 24-bit-per-pixel or 32-bit-per-pixel 

    else
        pbmi = (PBITMAPINFO)LocalAlloc(LPTR,
            sizeof(BITMAPINFOHEADER));

    // Initialize the fields in the BITMAPINFO structure.  

    pbmi->bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    pbmi->bmiHeader.biWidth = bmp.bmWidth;
    pbmi->bmiHeader.biHeight = bmp.bmHeight;
    pbmi->bmiHeader.biPlanes = bmp.bmPlanes;
    pbmi->bmiHeader.biBitCount = bmp.bmBitsPixel;
    if (cClrBits < 24)
        pbmi->bmiHeader.biClrUsed = (1 << cClrBits);

    // If the bitmap is not compressed, set the BI_RGB flag.  
    pbmi->bmiHeader.biCompression = BI_RGB;

    // Compute the number of bytes in the array of color  
    // indices and store the result in biSizeImage.  
    // The width must be DWORD aligned unless the bitmap is RLE 
    // compressed. 
    pbmi->bmiHeader.biSizeImage = ((pbmi->bmiHeader.biWidth * cClrBits + 31) & ~31) / 8
        * pbmi->bmiHeader.biHeight;
    // Set biClrImportant to 0, indicating that all of the  
    // device colors are important.  
    pbmi->bmiHeader.biClrImportant = 0;
    return pbmi;
}

void CreateBMPFile(LPSTR pszFile, PBITMAPINFO pbi, HBITMAP hBMP, HDC hDC)
{
    HANDLE hf;                 // file handle  
    BITMAPFILEHEADER hdr;       // bitmap file-header  
    PBITMAPINFOHEADER pbih;     // bitmap info-header  
    LPBYTE lpBits;              // memory pointer  
    DWORD dwTotal;              // total count of bytes  
    DWORD cb;                   // incremental count of bytes  
    BYTE* hp;                   // byte pointer  
    DWORD dwTmp;

    pbih = (PBITMAPINFOHEADER)pbi;
    lpBits = (LPBYTE)GlobalAlloc(GMEM_FIXED, pbih->biSizeImage);


    // Retrieve the color table (RGBQUAD array) and the bits  
    // (array of palette indices) from the DIB.  
    GetDIBits(hDC, hBMP, 0, (WORD)pbih->biHeight, lpBits, pbi,
        DIB_RGB_COLORS);

    // Create the .BMP file.  
    hf = CreateFileA(pszFile,
        GENERIC_READ | GENERIC_WRITE,
        (DWORD)0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        (HANDLE)NULL);

    hdr.bfType = 0x4d42;        // 0x42 = "B" 0x4d = "M"  
    // Compute the size of the entire file.  
    hdr.bfSize = (DWORD)(sizeof(BITMAPFILEHEADER) +
        pbih->biSize + pbih->biClrUsed
        * sizeof(RGBQUAD) + pbih->biSizeImage);
    hdr.bfReserved1 = 0;
    hdr.bfReserved2 = 0;

    // Compute the offset to the array of color indices.  
    hdr.bfOffBits = (DWORD) sizeof(BITMAPFILEHEADER) +
        pbih->biSize + pbih->biClrUsed
        * sizeof(RGBQUAD);

    // Copy the BITMAPFILEHEADER into the .BMP file.  
    WriteFile(hf, (LPVOID)&hdr, sizeof(BITMAPFILEHEADER),
        (LPDWORD)&dwTmp, NULL);

    // Copy the BITMAPINFOHEADER and RGBQUAD array into the file.  
    WriteFile(hf, (LPVOID)pbih, sizeof(BITMAPINFOHEADER)
        + pbih->biClrUsed * sizeof(RGBQUAD),
        (LPDWORD)&dwTmp, (NULL));

    // Copy the array of color indices into the .BMP file.  
    dwTotal = cb = pbih->biSizeImage;
    hp = lpBits;
    WriteFile(hf, (LPSTR)hp, (int)cb, (LPDWORD)&dwTmp, NULL);

    // Close the .BMP file.  
    CloseHandle(hf);

    // Free memory.  
    GlobalFree((HGLOBAL)lpBits);
}

void takeScreenshot(int width, int height)
{
    // get the device context of the screen
    HDC hScreenDC = CreateDCA("DISPLAY", NULL, NULL, NULL);
    // and a device context to put it in
    HDC hMemoryDC = CreateCompatibleDC(hScreenDC);

    //int width =  1920; //GetDeviceCaps(hScreenDC, HORZRES);
    //int height = 1080; //GetDeviceCaps(hScreenDC, VERTRES);

    // maybe worth checking these are positive values
    HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, width, height);

    // get a new bitmap
    HBITMAP hOldBitmap = (HBITMAP)SelectObject(hMemoryDC, hBitmap);

    BitBlt(hMemoryDC, 0, 0, width, height, hScreenDC, 0, 0, SRCCOPY);
    hBitmap = (HBITMAP)SelectObject(hMemoryDC, hOldBitmap);


    // now your image is held in hBitmap. You can save it or do whatever with it

    CHAR wName[64] = "scrsh.bmp";

    CreateBMPFile(
        wName,
        CreateBitmapInfoStruct(hBitmap),
        hBitmap,
        hMemoryDC);


    // clean up
    DeleteDC(hMemoryDC);
    DeleteDC(hScreenDC);
}

int _cdecl wmain(_In_ int argc, _In_reads_(argc)wchar_t* argv[])
{
    //FILE* input = NULL;
    //input = fopen("C:\\1.exe", "rb");
    //fseek(input, 0L, SEEK_END);
    //int sz = ftell(input) + 4 + 4;
    ////seek back:
    //fseek(input, 0L, SEEK_SET);


    ULONG       ulRetCode = CXN_SUCCESS;
    WSADATA     WSAData = { 0 };
    SOCKADDR_BTH RemoteBthAddr = { 0 };

    // get pc name
    DWORD pcNameLen = BTH_MAX_NAME_SIZE;
    if (!GetComputerNameW(g_szMyName, &pcNameLen))
    {
        outputMut.lock();
        wprintf(L"=CRITICAL= | GetComputerName() call failed. WSAGetLastError=[%d]\n", WSAGetLastError());
        outputMut.unlock();
        ulRetCode = CXN_ERROR;
    }

    if (argc >= 3)
    {
        // get resolution from cmd
        gWidth = _wtoi(argv[1]);
        gHeight = _wtoi(argv[2]);
    }

    // 
    // Ask for Winsock version 2.2. 
    // 
    if (CXN_SUCCESS == ulRetCode)
    {
        ulRetCode = WSAStartup(MAKEWORD(2, 2), &WSAData);
        if (CXN_SUCCESS != ulRetCode)
        {
            outputMut.lock();
            wprintf(L"-FATAL- | Unable to initialize Winsock version 2.2\n");
            outputMut.unlock();
        }
    }

    std::thread server(RunServerMode, 0);
    server.detach();

    int mode = 0;
    char arg[512] = { 0 };

    if (CXN_SUCCESS == ulRetCode)
    {
        while (1)
        {
            outputMut.lock();
            printf("connect to device: 1 - by address; 2 - by name\n");
            outputMut.unlock();
            scanf("%i", &mode);

            if (mode == 1)
            {
                outputMut.lock();
                printf("Enter address\n");
                outputMut.unlock();
                wscanf(L"%s", &g_szRemoteAddr);
            }
            else if (mode == 2)
            {
                outputMut.lock();
                printf("Enter name\n");
                outputMut.unlock();
                wscanf(L"%s", &g_szRemoteName);
            }
            else
            {
                outputMut.lock();
                printf("wrong input. try again\n");
                outputMut.unlock();
                continue;
            }

            while (1)
            {
                outputMut.lock();
                printf("now choose: 1 - get screenshot; 2<PATH> - get file\n");
                outputMut.unlock();
                scanf("%s", &arg);
                if (arg[0] == '1')
                {
                    break;
                }
                else if (arg[0] == '2' && arg[1] != '\0')
                {
                    memcpy(g_szPath, &arg[1], strlen(&arg[1]));
                    break;
                }
                else
                {
                    outputMut.lock();
                    printf("try again\n");
                    outputMut.unlock();
                }
            }

            // 
            // Note, this app "prefers" the name if provided, but it is app-specific 
            // Other applications may provide more generic treatment. 
            // 
            if (L'\0' != g_szRemoteName[0]) {
                // 
                // Get address from the name of the remote device and run the application 
                // in client mode 
                // 
                ulRetCode = NameToBthAddr(g_szRemoteName, &RemoteBthAddr);
                if (CXN_SUCCESS != ulRetCode)
                {
                    outputMut.lock();
                    wprintf(L"-FATAL- | Unable to get address of the remote radio having name %s\n", g_szRemoteName);
                    outputMut.unlock();
                }

                if (CXN_SUCCESS == ulRetCode)
                {
                    ulRetCode = RunClientMode(RemoteBthAddr, 1, (arg[0] == '1' ? 3 : 4));
                }

                memset(g_szRemoteName, 0, sizeof(g_szRemoteName));
            }
            else if (L'\0' != g_szRemoteAddr[0])
            {

                // 
                // Get address from formated address-string of the remote device and 
                // run the application in client mode 
                // 
                int iAddrLen = sizeof(RemoteBthAddr);
                ulRetCode = WSAStringToAddressW(
                    g_szRemoteAddr,
                    AF_BTH,
                    NULL,
                    (LPSOCKADDR)&RemoteBthAddr,
                    &iAddrLen);
                if (CXN_SUCCESS != ulRetCode)
                {
                    outputMut.lock();
                    wprintf(L"-FATAL- | Unable to get address of the remote radio having formated address-string %s\n", g_szRemoteAddr);
                    outputMut.unlock();
                }

                if (CXN_SUCCESS == ulRetCode)
                {
                    ulRetCode = RunClientMode(RemoteBthAddr, 1, (arg[0] == '1' ? 3 : 4));
                }

                memset(g_szRemoteAddr, 0, sizeof(g_szRemoteAddr));
            }

            memset(arg, '\0', sizeof(arg));
        }
    }

    system("pause");

    return(int)ulRetCode;
}


// 
// NameToBthAddr converts a bluetooth device name to a bluetooth address, 
// if required by performing inquiry with remote name requests. 
// This function demonstrates device inquiry, with optional LUP flags. 
// 
ULONG NameToBthAddr(_In_ const LPWSTR pszRemoteName, _Out_ PSOCKADDR_BTH pRemoteBtAddr)
{
    INT             iResult = CXN_SUCCESS;
    BOOL            bContinueLookup = FALSE, bRemoteDeviceFound = FALSE;
    ULONG           ulFlags = 0, ulPQSSize = sizeof(WSAQUERYSET);
    HANDLE          hLookup = NULL;
    PWSAQUERYSET    pWSAQuerySet = NULL;

    ZeroMemory(pRemoteBtAddr, sizeof(*pRemoteBtAddr));

    pWSAQuerySet = (PWSAQUERYSET)calloc(ulPQSSize, 1);
    //pWSAQuerySet = (PWSAQUERYSET)HeapAlloc(GetProcessHeap(),
    //    HEAP_ZERO_MEMORY,
    //    ulPQSSize);
    if (NULL == pWSAQuerySet)
    {
        iResult = STATUS_NO_MEMORY;
        outputMut.lock();
        wprintf(L"!ERROR! | Unable to allocate memory for WSAQUERYSET\n");
        outputMut.unlock();
    }

    // 
    // Search for the device with the correct name 
    // 
    if (CXN_SUCCESS == iResult)
    {

        for (INT iRetryCount = 0;
            !bRemoteDeviceFound && (iRetryCount < CXN_MAX_INQUIRY_RETRY);
            iRetryCount++)
        {
            // 
            // WSALookupService is used for both service search and device inquiry 
            // LUP_CONTAINERS is the flag which signals that we're doing a device inquiry. 
            // 
            ulFlags = LUP_CONTAINERS;

            // 
            // Friendly device name (if available) will be returned in lpszServiceInstanceName 
            // 
            ulFlags |= LUP_RETURN_NAME;

            // 
            // BTH_ADDR will be returned in lpcsaBuffer member of WSAQUERYSET 
            // 
            ulFlags |= LUP_RETURN_ADDR;

            if (0 == iRetryCount)
            {
                //wprintf(L"*INFO* | Inquiring device from cache...\n");
            }
            else
            {
                // 
                // Flush the device cache for all inquiries, except for the first inquiry 
                // 
                // By setting LUP_FLUSHCACHE flag, we're asking the lookup service to do 
                // a fresh lookup instead of pulling the information from device cache. 
                // 
                ulFlags |= LUP_FLUSHCACHE;

                // 
                // Pause for some time before all the inquiries after the first inquiry 
                // 
                // Remote Name requests will arrive after device inquiry has 
                // completed.  Without a window to receive IN_RANGE notifications, 
                // we don't have a direct mechanism to determine when remote 
                // name requests have completed. 
                // 
                outputMut.lock();
                wprintf(L"*INFO* | Unable to find device.  Waiting for %d seconds before re-inquiry...\n", CXN_DELAY_NEXT_INQUIRY);
                outputMut.unlock();
                Sleep(CXN_DELAY_NEXT_INQUIRY * 1000);

                //wprintf(L"*INFO* | Inquiring device ...\n");
            }

            // 
            // Start the lookup service 
            // 
            iResult = CXN_SUCCESS;
            hLookup = 0;
            bContinueLookup = FALSE;
            ZeroMemory(pWSAQuerySet, ulPQSSize);
            pWSAQuerySet->dwNameSpace = NS_BTH;
            pWSAQuerySet->dwSize = sizeof(WSAQUERYSET);
            iResult = WSALookupServiceBegin(pWSAQuerySet, ulFlags, &hLookup);

            // 
            // Even if we have an error, we want to continue until we 
            // reach the CXN_MAX_INQUIRY_RETRY 
            // 
            if ((NO_ERROR == iResult) && (NULL != hLookup))
            {
                bContinueLookup = TRUE;
            }
            else if (0 < iRetryCount)
            {
                outputMut.lock();
                wprintf(L"=CRITICAL= | WSALookupServiceBegin() failed with error code %d, WSAGetLastError = %d\n", iResult, WSAGetLastError());
                outputMut.unlock();
                break;
            }

            while (bContinueLookup)
            {
                // 
                // Get information about next bluetooth device 
                // 
                // Note you may pass the same WSAQUERYSET from LookupBegin 
                // as long as you don't need to modify any of the pointer 
                // members of the structure, etc. 
                //  
                if (NO_ERROR == WSALookupServiceNext(hLookup,
                    ulFlags,
                    &ulPQSSize,
                    pWSAQuerySet))
                {

                    // 
                    // Compare the name to see if this is the device we are looking for. 
                    // 
                    if ((pWSAQuerySet->lpszServiceInstanceName != NULL) &&
                        (CXN_SUCCESS == _wcsicmp(pWSAQuerySet->lpszServiceInstanceName, pszRemoteName)))
                    {
                        // 
                        // Found a remote bluetooth device with matching name. 
                        // Get the address of the device and exit the lookup. 
                        // 
                        CopyMemory(pRemoteBtAddr,
                            (PSOCKADDR_BTH)pWSAQuerySet->lpcsaBuffer->RemoteAddr.lpSockaddr,
                            sizeof(*pRemoteBtAddr));
                        bRemoteDeviceFound = TRUE;
                        bContinueLookup = FALSE;
                    }
                }
                else {
                    iResult = WSAGetLastError();
                    if (WSA_E_NO_MORE == iResult)
                    { //No more data 
                        // 
                        // No more devices found.  Exit the lookup. 
                        // 
                        bContinueLookup = FALSE;
                    }
                    else if (WSAEFAULT == iResult)
                    {
                        // 
                        // The buffer for QUERYSET was insufficient. 
                        // In such case 3rd parameter "ulPQSSize" of function "WSALookupServiceNext()" receives 
                        // the required size.  So we can use this parameter to reallocate memory for QUERYSET. 
                        // 
                        //HeapFree(GetProcessHeap(), 0, pWSAQuerySet);
                        free(pWSAQuerySet);
                        pWSAQuerySet = (PWSAQUERYSET)calloc(ulPQSSize, 1);
                        //pWSAQuerySet = (PWSAQUERYSET)HeapAlloc(GetProcessHeap(),
                        //    HEAP_ZERO_MEMORY,
                        //    ulPQSSize);
                        if (NULL == pWSAQuerySet)
                        {
                            outputMut.lock();
                            wprintf(L"!ERROR! | Unable to allocate memory for WSAQERYSET\n");
                            outputMut.unlock();
                            iResult = STATUS_NO_MEMORY;
                            bContinueLookup = FALSE;
                        }
                    }
                    else
                    {
                        outputMut.lock();
                        wprintf(L"=CRITICAL= | WSALookupServiceNext() failed with error code %d\n", iResult);
                        outputMut.unlock();
                        bContinueLookup = FALSE;
                    }
                }
            }

            // 
            // End the lookup service 
            // 
            WSALookupServiceEnd(hLookup);

            if (STATUS_NO_MEMORY == iResult)
            {
                break;
            }
        }
    }

    if (NULL != pWSAQuerySet)
    {
        //HeapFree(GetProcessHeap(), 0, pWSAQuerySet);
        free(pWSAQuerySet);
        pWSAQuerySet = NULL;
    }

    if (bRemoteDeviceFound)
    {
        iResult = CXN_SUCCESS;
    }
    else
    {
        iResult = CXN_ERROR;
    }

    return iResult;
}

// 
// RunClientMode runs the application in client mode.  It opens a socket, connects it to a 
// remote socket, transfer some data over the connection and closes the connection. 
// 
ULONG RunClientMode(_In_ SOCKADDR_BTH RemoteAddr, _In_ int iMaxCxnCycles, _In_ int mode, _In_ char* filePathToSend)
{
    ULONG           ulRetCode = CXN_SUCCESS;
    int             iCxnCount = 0;
    //wchar_t*        pszData = NULL;
    char* pszData = NULL;
    SOCKET          LocalSocket = INVALID_SOCKET;
    SOCKADDR_BTH    SockAddrBthServer = RemoteAddr;
    int             sz = 0;

    if (CXN_SUCCESS == ulRetCode)
    {
        // 
        // Setting address family to AF_BTH indicates winsock2 to use Bluetooth sockets 
        // Port should be set to 0 if ServiceClassId is spesified. 
        // 
        SockAddrBthServer.addressFamily = AF_BTH;
        SockAddrBthServer.serviceClassId = g_guidServiceClass;
        SockAddrBthServer.port = 0;
        int szName;
        int szDeviceName;
        int sizeFile; 
        char* tmp = NULL;

        if (mode == 1 || mode == 2) // 1 || 2 // send file
        {
            FILE* input = NULL;

            if (mode == 1)
            {
                takeScreenshot(gWidth, gHeight);
                input = fopen("scrsh.bmp", "rb");
                if (input == NULL)
                {
                    outputMut.lock();
                    printf("open file error. try again\n");
                    outputMut.unlock();
                }
            }
            else if (mode == 2)
            {
                input = fopen(filePathToSend, "rb");
                if (input == NULL)
                {
                    outputMut.lock();
                    printf("fopen error\n");
                    outputMut.unlock();
                    return 2;
                }
            }
            else
            {
                outputMut.lock();
                printf("wrong input");
                outputMut.unlock();
            }

            fseek(input, 0L, SEEK_END);
            sizeFile = ftell(input);
            sz = sizeFile + 4 + 4;
            //seek back:
            fseek(input, 0L, SEEK_SET);

            if (mode == 1)
            {
                szName = strlen("scrsh.bmp");
            }
            else
            {
                // set name len
                tmp = filePathToSend;
                char* pch = strtok(filePathToSend, "\\");
                while (pch != NULL)
                {
                    tmp = pch;
                    pch = strtok(NULL, "\\");
                }
                szName = strlen(tmp);
            }
            sz += szName;

            //pszData = (char*)HeapAlloc(GetProcessHeap(),
            //    HEAP_ZERO_MEMORY,
            //    sz);
            pszData = (char*)calloc(sz, 1);
            if (NULL == pszData)
            {
                ulRetCode = STATUS_NO_MEMORY;
                outputMut.lock();
                wprintf(L"=CRITICAL= | HeapAlloc failed | out of memory, gle = [%d] \n", GetLastError());
                outputMut.unlock();
            }

            // set name len
            memcpy(&pszData[4], &szName, 4);

            // set file name
            if (mode == 1)
            {
                memcpy(&pszData[8], "scrsh.bmp", strlen("scrsh.bmp"));
            }
            else
            {
                memcpy(&pszData[8], tmp, strlen(tmp));
            }

            // set size
            memcpy(&pszData[0], &sz, 4);
            //int A = HeapSize(GetProcessHeap(), 0, pszData);
            fread((void*)&pszData[8 + szName], sizeof(char), sizeFile, input);
            //A=HeapSize(GetProcessHeap(), 0, pszData);
            //pszData[A] = '\\';
            
            fclose(input);
        }
        else if (mode == 3 || mode == 4) // send request
        {
            szDeviceName = wcslen(g_szMyName) * sizeof(wchar_t);
            szName = strlen(g_szPath);
            sz = 4 + 4 + szDeviceName + 4 + szName;
            //pszData = (char*)HeapAlloc(GetProcessHeap(),
            //    HEAP_ZERO_MEMORY,
            //    sz);
            pszData = (char*)calloc(sz, 1);
            if (NULL == pszData)
            {
                ulRetCode = STATUS_NO_MEMORY;
                outputMut.lock();
                wprintf(L"=CRITICAL= | HeapAlloc failed | out of memory, gle = [%d] \n", GetLastError());
                outputMut.unlock();
            }

            // set device name len
            memcpy(&pszData[4], &szDeviceName, 4);
            // set device name
            memcpy(&pszData[8], &g_szMyName, szDeviceName);

            int requestCode;
            if (mode == 3) //screen
            {
                // set request code
                requestCode = -1;
            }
            else // file
            {
                // set file name len
                memcpy(&pszData[8 + szDeviceName], &szName, 4);
                // set file name
                memcpy(&pszData[8 + szDeviceName + 4], &g_szPath, szName);

                // set request code
                requestCode = -2;
            }
            memcpy(&pszData[0], &requestCode, 4);

        }
        else
        {
            outputMut.lock();
            printf("error\n");
            outputMut.unlock();
        }
    }

    if (CXN_SUCCESS == ulRetCode)
    {
        // 
        // Run the connection/data-transfer for user specified number of cycles 
        // 
        for (iCxnCount = 0;
            (0 == ulRetCode) && (iCxnCount < iMaxCxnCycles || iMaxCxnCycles == 0);
            iCxnCount++)
        {
            // 
            // Open a bluetooth socket using RFCOMM protocol 
            // 
            LocalSocket = socket(AF_BTH, SOCK_STREAM, BTHPROTO_RFCOMM);
            if (INVALID_SOCKET == LocalSocket)
            {
                outputMut.lock();
                wprintf(L"=CRITICAL= | socket() call failed. WSAGetLastError = [%d]\n", WSAGetLastError());
                outputMut.unlock();
                ulRetCode = CXN_ERROR;
                break;
            }

            // 
            // Connect the socket (pSocket) to a given remote socket represented by address (pServerAddr) 
            // 
            if (SOCKET_ERROR == connect(LocalSocket,
                (struct sockaddr*) & SockAddrBthServer,
                sizeof(SOCKADDR_BTH)))
            {
                outputMut.lock();
                wprintf(L"=CRITICAL= | connect() call failed. WSAGetLastError=[%d]\n", WSAGetLastError());
                outputMut.unlock();
                ulRetCode = CXN_ERROR;
                break;
            }

            // 
            // send() call indicates winsock2 to send the given data 
            // of a specified length over a given connection. 
            //
            if (SOCKET_ERROR == send(LocalSocket,
                (char*)pszData,
                sz,
                0))
            {
                outputMut.lock();
                wprintf(L"=CRITICAL= | send() call failed w/socket = [0x%I64X], szData = [%p]. WSAGetLastError=[%d]\n", (ULONG64)LocalSocket, pszData, WSAGetLastError());
                outputMut.unlock();
                ulRetCode = CXN_ERROR;
                break;
            }

            // 
            // Close the socket 
            // 
            if (SOCKET_ERROR == closesocket(LocalSocket))
            {
                outputMut.lock();
                wprintf(L"=CRITICAL= | closesocket() call failed w/socket = [0x%I64X]. WSAGetLastError=[%d]\n", (ULONG64)LocalSocket, WSAGetLastError());
                outputMut.unlock();
                ulRetCode = CXN_ERROR;
                break;
            }

            LocalSocket = INVALID_SOCKET;

        }
    }

    if (INVALID_SOCKET != LocalSocket)
    {
        closesocket(LocalSocket);
        LocalSocket = INVALID_SOCKET;
    }

    if (NULL != pszData)
    {
        //HeapFree(GetProcessHeap(), 0, pszData);
        free(pszData);
        pszData = NULL;
    }

    return(ulRetCode);
}

// 
// RunServerMode runs the application in server mode.  It opens a socket, connects it to a 
// remote socket, transfer some data over the connection and closes the connection. 
// 

#define CXN_INSTANCE_STRING L"Sample Bluetooth Server" 

ULONG RunServerMode(_In_ int iMaxCxnCycles)
{
    ULONG           ulRetCode = CXN_SUCCESS;
    int             iAddrLen = sizeof(SOCKADDR_BTH);
    int             iCxnCount = 0;
    UINT            iLengthReceived = 0;
    UINT            uiTotalLengthReceived;
    size_t          cbInstanceNameSize = 0;
    char*           pszDataBuffer = NULL;
    char*           pszName = NULL;
    char*           pszDataBufferIndex = NULL;
    wchar_t*        pszInstanceName = NULL;
    wchar_t         szThisComputerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD           dwLenComputerName = MAX_COMPUTERNAME_LENGTH + 1;
    SOCKET          LocalSocket = INVALID_SOCKET;
    SOCKET          ClientSocket = INVALID_SOCKET;
    WSAQUERYSET     wsaQuerySet = { 0 };
    SOCKADDR_BTH    SockAddrBthLocal = { 0 };
    LPCSADDR_INFO   lpCSAddrInfo = NULL;
    HRESULT         res;

    // 
    // This fixed-size allocation can be on the stack assuming the 
    // total doesn't cause a stack overflow (depends on your compiler settings) 
    // However, they are shown here as dynamic to allow for easier expansion 
    // 
    lpCSAddrInfo = (LPCSADDR_INFO)calloc(sizeof(CSADDR_INFO), 1);
    //lpCSAddrInfo = (LPCSADDR_INFO)HeapAlloc(GetProcessHeap(),
    //    HEAP_ZERO_MEMORY,
    //    sizeof(CSADDR_INFO));
    if (NULL == lpCSAddrInfo)
    {
        outputMut.lock();
        wprintf(L"!ERROR! | Unable to allocate memory for CSADDR_INFO\n");
        outputMut.unlock();
        ulRetCode = CXN_ERROR;
    }

    if (CXN_SUCCESS == ulRetCode)
    {

        if (!GetComputerName(szThisComputerName, &dwLenComputerName))
        {
            outputMut.lock();
            wprintf(L"=CRITICAL= | GetComputerName() call failed. WSAGetLastError=[%d]\n", WSAGetLastError());
            outputMut.unlock();
            ulRetCode = CXN_ERROR;
        }
    }

    // 
    // Open a bluetooth socket using RFCOMM protocol 
    // 
    if (CXN_SUCCESS == ulRetCode)
    {
        LocalSocket = socket(AF_BTH, SOCK_STREAM, BTHPROTO_RFCOMM);
        if (INVALID_SOCKET == LocalSocket)
        {
            outputMut.lock();
            wprintf(L"=CRITICAL= | socket() call failed. WSAGetLastError = [%d]\n", WSAGetLastError());
            outputMut.unlock();
            ulRetCode = CXN_ERROR;
        }
    }

    if (CXN_SUCCESS == ulRetCode)
    {

        // 
        // Setting address family to AF_BTH indicates winsock2 to use Bluetooth port 
        // 
        SockAddrBthLocal.addressFamily = AF_BTH;
        SockAddrBthLocal.port = BT_PORT_ANY;                                             ///PORT

        // 
        // bind() associates a local address and port combination 
        // with the socket just created. This is most useful when 
        // the application is a server that has a well-known port 
        // that clients know about in advance. 
        // 
        if (SOCKET_ERROR == bind(LocalSocket,
            (struct sockaddr*) & SockAddrBthLocal,
            sizeof(SOCKADDR_BTH)))
        {
            outputMut.lock();
            wprintf(L"=CRITICAL= | bind() call failed w/socket = [0x%I64X]. WSAGetLastError=[%d]\n", (ULONG64)LocalSocket, WSAGetLastError());
            outputMut.unlock();
            ulRetCode = CXN_ERROR;
        }
    }

    if (CXN_SUCCESS == ulRetCode)
    {

        ulRetCode = getsockname(LocalSocket,
            (struct sockaddr*) & SockAddrBthLocal,
            &iAddrLen);
        if (SOCKET_ERROR == ulRetCode)
        {
            outputMut.lock();
            wprintf(L"=CRITICAL= | getsockname() call failed w/socket = [0x%I64X]. WSAGetLastError=[%d]\n", (ULONG64)LocalSocket, WSAGetLastError());
            outputMut.unlock();
            ulRetCode = CXN_ERROR;
        }
    }

    if (CXN_SUCCESS == ulRetCode)
    {
        // 
        // CSADDR_INFO 
        // 
        lpCSAddrInfo[0].LocalAddr.iSockaddrLength = sizeof(SOCKADDR_BTH);
        lpCSAddrInfo[0].LocalAddr.lpSockaddr = (LPSOCKADDR)&SockAddrBthLocal;
        lpCSAddrInfo[0].RemoteAddr.iSockaddrLength = sizeof(SOCKADDR_BTH);
        lpCSAddrInfo[0].RemoteAddr.lpSockaddr = (LPSOCKADDR)&SockAddrBthLocal;
        lpCSAddrInfo[0].iSocketType = SOCK_STREAM;
        lpCSAddrInfo[0].iProtocol = BTHPROTO_RFCOMM;

        // 
        // If we got an address, go ahead and advertise it. 
        // 
        ZeroMemory(&wsaQuerySet, sizeof(WSAQUERYSET));
        wsaQuerySet.dwSize = sizeof(WSAQUERYSET);
        wsaQuerySet.lpServiceClassId = (LPGUID)&g_guidServiceClass;

        // 
        // Adding a byte to the size to account for the space in the 
        // format string in the swprintf call. This will have to change if converted 
        // to UNICODE 
        // 
        res = StringCchLength(szThisComputerName, sizeof(szThisComputerName), &cbInstanceNameSize);
        if (FAILED(res))
        {
            outputMut.lock();
            wprintf(L"-FATAL- | ComputerName specified is too large\n");
            outputMut.unlock();
            ulRetCode = CXN_ERROR;
        }
    }

    if (CXN_SUCCESS == ulRetCode)
    {
        cbInstanceNameSize += sizeof(CXN_INSTANCE_STRING) + 1;
        pszInstanceName = (LPWSTR)calloc(cbInstanceNameSize, 1);
        //pszInstanceName = (LPWSTR)HeapAlloc(GetProcessHeap(),
        //    HEAP_ZERO_MEMORY,
        //    cbInstanceNameSize);
        if (NULL == pszInstanceName)
        {
            outputMut.lock();
            wprintf(L"-FATAL- | HeapAlloc failed | out of memory | gle = [%d] \n", GetLastError());
            outputMut.unlock();
            ulRetCode = CXN_ERROR;
        }
    }

    if (CXN_SUCCESS == ulRetCode)
    {
        WCHAR wComment[128] = L"Example Service instance registered in the directory service through RnR";

        StringCbPrintf(pszInstanceName, cbInstanceNameSize, L"%s %s", szThisComputerName, CXN_INSTANCE_STRING);
        wsaQuerySet.lpszServiceInstanceName = pszInstanceName;
        wsaQuerySet.lpszComment = wComment;
        wsaQuerySet.dwNameSpace = NS_BTH;
        wsaQuerySet.dwNumberOfCsAddrs = 1;      // Must be 1. 
        wsaQuerySet.lpcsaBuffer = lpCSAddrInfo; // Req'd. 

        // 
        // As long as we use a blocking accept(), we will have a race 
        // between advertising the service and actually being ready to 
        // accept connections.  If we use non-blocking accept, advertise 
        // the service after accept has been called. 
        // 
        if (SOCKET_ERROR == WSASetService(&wsaQuerySet, RNRSERVICE_REGISTER, 0))
        {
            outputMut.lock();
            wprintf(L"=CRITICAL= | WSASetService() call failed. WSAGetLastError=[%d]\n", WSAGetLastError());
            outputMut.unlock();
            ulRetCode = CXN_ERROR;
        }
    }

    // 
    // listen() call indicates winsock2 to listen on a given socket for any incoming connection. 
    // 
    if (CXN_SUCCESS == ulRetCode) {
        if (SOCKET_ERROR == listen(LocalSocket, CXN_DEFAULT_LISTEN_BACKLOG))
        {
            outputMut.lock();
            wprintf(L"=CRITICAL= | listen() call failed w/socket = [0x%I64X]. WSAGetLastError=[%d]\n", (ULONG64)LocalSocket, WSAGetLastError());
            outputMut.unlock();
            ulRetCode = CXN_ERROR;
        }
    }

    if (CXN_SUCCESS == ulRetCode)
    {

        for (iCxnCount = 0;
            (CXN_SUCCESS == ulRetCode) && ((iCxnCount < iMaxCxnCycles) || (iMaxCxnCycles == 0));
            iCxnCount++)
        {
            // 
            // accept() call indicates winsock2 to wait for any 
            // incoming connection request from a remote socket. 
            // If there are already some connection requests on the queue, 
            // then accept() extracts the first request and creates a new socket and 
            // returns the handle to this newly created socket. This newly created 
            // socket represents the actual connection that connects the two sockets. 
            // 
            ClientSocket = accept(LocalSocket, NULL, NULL);
            if (INVALID_SOCKET == ClientSocket)
            {
                outputMut.lock();
                wprintf(L"=CRITICAL= | accept() call failed. WSAGetLastError=[%d]\n", WSAGetLastError());
                outputMut.unlock();
                ulRetCode = CXN_ERROR;
                break; // Break out of the for loop 
            }

            // 
            // Read data from the incoming stream 
            // 
            BOOL bContinue = TRUE;

            void* pTmp = NULL;
            int   recvdTmp = 0;
            int   toRecvTmp = 0;

            int sz[3] = { 0 };

            pTmp = (void*)sz;
            toRecvTmp = 8;
            while (toRecvTmp != 0)
            {
                //recv size
                recvdTmp = recv(
                    ClientSocket,
                    (char*)pTmp,
                    toRecvTmp,
                    0);
                pTmp = (char*)pTmp + recvdTmp;
                toRecvTmp -= recvdTmp;
            }
            pTmp = NULL;
            toRecvTmp = 0;

            if (sz[0] > 0)
            {
                //name allocate
                pszName = (char*)calloc(sz[1] + 1, 1);
                //pszName = (char*)HeapAlloc(GetProcessHeap(),
                //    HEAP_ZERO_MEMORY,
                //    sz[1] + 1);
                if (NULL == pszName)
                {
                    outputMut.lock();
                    wprintf(L"-FATAL- | HeapAlloc failed | out of memory | gle = [%d] \n", GetLastError());
                    outputMut.unlock();
                    ulRetCode = CXN_ERROR;
                    break;
                }

                pTmp = (void*)pszName;
                toRecvTmp = sz[1];
                while (toRecvTmp != 0)
                {
                    //recv fname
                    recvdTmp = recv(
                        ClientSocket,
                        (char*)pTmp,
                        toRecvTmp,
                        0);
                    pTmp = (char*)pTmp + recvdTmp;
                    toRecvTmp -= recvdTmp;
                }
                pTmp = NULL;
                toRecvTmp = 0;

                pszName[sz[1]] = '\0';

                pszDataBuffer = (char*)calloc(sz[0], 1);
                //pszDataBuffer = (char*)HeapAlloc(GetProcessHeap(),
                //    HEAP_ZERO_MEMORY,
                //    sz[0]);
                if (NULL == pszDataBuffer)
                {
                    outputMut.lock();
                    wprintf(L"-FATAL- | HeapAlloc failed | out of memory | gle = [%d] \n", GetLastError());
                    outputMut.unlock();
                    ulRetCode = CXN_ERROR;
                    break;
                }

                sz[0] -= (8 + sz[1]);
            }
            else
            {
                wchar_t* remoteName = (wchar_t*)calloc(sz[1] + 1, 1);
                //wchar_t* remoteName = (wchar_t*)HeapAlloc(GetProcessHeap(),
                //    HEAP_ZERO_MEMORY,
                //    sz[1] + 1);
                if (NULL == remoteName)
                {
                    outputMut.lock();
                    wprintf(L"-FATAL- | HeapAlloc failed | out of memory | gle = [%d] \n", GetLastError());
                    outputMut.unlock();
                    ulRetCode = CXN_ERROR;
                    break;
                }

                pTmp = (void*)remoteName;
                toRecvTmp = sz[1];
                while (toRecvTmp != 0)
                {
                    //recv remote name
                    recvdTmp = recv(
                        ClientSocket,
                        (char*)pTmp,
                        toRecvTmp,
                        0);
                    pTmp = (char*)pTmp + recvdTmp;
                    toRecvTmp -= recvdTmp;
                }
                pTmp = NULL;
                toRecvTmp = 0;

                remoteName[sz[1] / 2] = L'\0';

                SOCKADDR_BTH RemoteBthAddr = { 0 };
                ulRetCode = NameToBthAddr(remoteName, &RemoteBthAddr);
                if (CXN_SUCCESS != ulRetCode)
                {
                    outputMut.lock();
                    wprintf(L"-FATAL- | Unable to get address of the remote radio having name %s\n", g_szRemoteName);
                    outputMut.unlock();
                }

                if (sz[0] == -1) // screen
                {
                    RunClientMode(RemoteBthAddr, 1, 1);

                    if (NULL != remoteName)
                    {
                        //HeapFree(GetProcessHeap(), 0, remoteName);
                        free(remoteName);
                        remoteName = NULL;
                    }
                    //wprintf(L"Ok - server thread\n");
                    continue;
                }
                else if (sz[0] == -2) // file
                {
                    pTmp = (void*)(&sz[2]);
                    toRecvTmp = 4;
                    while (toRecvTmp != 0)
                    {
                        // recv file name size
                        recvdTmp = recv(
                            ClientSocket,
                            (char*)pTmp,
                            toRecvTmp,
                            0);
                        pTmp = (char*)pTmp + recvdTmp;
                        toRecvTmp -= recvdTmp;
                    }
                    pTmp = NULL;
                    toRecvTmp = 0;

                    char* fileName = (char*)calloc(sz[2] + 1, 1);
                    //char* fileName = (char*)HeapAlloc(GetProcessHeap(),
                    //    HEAP_ZERO_MEMORY,
                    //    sz[2] + 1);
                    if (NULL == fileName)
                    {
                        outputMut.lock();
                        wprintf(L"-FATAL- | HeapAlloc failed | out of memory | gle = [%d] \n", GetLastError());
                        outputMut.unlock();
                        ulRetCode = CXN_ERROR;
                        break;
                    }
                    fileName[sz[2]] = L'\0';

                    pTmp = (void*)fileName;
                    toRecvTmp = sz[2];
                    while (toRecvTmp != 0)
                    {
                        // recv file name size
                        recvdTmp = recv(
                            ClientSocket,
                            (char*)pTmp,
                            toRecvTmp,
                            0);
                        pTmp = (char*)pTmp + recvdTmp;
                        toRecvTmp -= recvdTmp;
                    }
                    pTmp = NULL;
                    toRecvTmp = 0;

                    outputMut.lock();
                    printf("Sending file to %ws: %s\n", remoteName, fileName);
                    outputMut.unlock();

                    RunClientMode(RemoteBthAddr, 1, 2, fileName);

                    if (NULL != fileName)
                    {
                        //HeapFree(GetProcessHeap(), 0, fileName);
                        free(fileName);
                        fileName = NULL;
                    }
                    //wprintf(L"Ok - server thread\n");
                    continue;
                }
                else
                {
                    outputMut.lock();
                    printf("error\n");
                    outputMut.unlock();
                }
            }

            pszDataBufferIndex = pszDataBuffer;
            uiTotalLengthReceived = 0;
            
            int percent;
            char dots[10];
            memset(dots, '>', 10);
            char spaces[10];
            memset(spaces, ' ', 10);

            outputMut.lock();
            while (bContinue && (uiTotalLengthReceived <= sz[0]))
            {
                percent = ((float)uiTotalLengthReceived / (float)sz[0]) * 100;
                printf("\rProgress: %i%% [", percent);
                fwrite(dots,   1,      percent / 10, stdout);
                fwrite(spaces, 1, 10 - percent / 10, stdout);
                printf("]");
                // 
                // recv() call indicates winsock2 to receive data 
                // of an expected length over a given connection. 
                // recv() may not be able to get the entire length 
                // of data at once.  In such case the return value, 
                // which specifies the number of bytes received, 
                // can be used to calculate how much more data is 
                // pending and accordingly recv() can be called again. 
                // 

                iLengthReceived = recv(ClientSocket,
                    (char*)pszDataBufferIndex,
                    (sz[0] - uiTotalLengthReceived),
                    0);

                switch (iLengthReceived)
                {
                case 0: // socket connection has been closed gracefully 
                    bContinue = FALSE;
                    break;

                case SOCKET_ERROR:
                    wprintf(L"=CRITICAL= | recv() call failed. WSAGetLastError=[%d]\n", WSAGetLastError());
                    bContinue = FALSE;
                    ulRetCode = CXN_ERROR;
                    break;

                default:

                    // 
                    // Make sure we have enough room 
                    // 
                    if (iLengthReceived > (sz[0] - uiTotalLengthReceived))
                    {
                        wprintf(L"=CRITICAL= | received too much data\n");
                        bContinue = FALSE;
                        ulRetCode = CXN_ERROR;
                        break;
                    }

                    pszDataBufferIndex += iLengthReceived;
                    uiTotalLengthReceived += iLengthReceived;
                    break;
                }
            }
            outputMut.unlock();



            if (CXN_SUCCESS == ulRetCode)
            {

                if (sz[0] != uiTotalLengthReceived)
                {
                    outputMut.lock();
                    wprintf(L"+WARNING+ | Data transfer aborted mid-stream. Actual Length = [%d]\n", uiTotalLengthReceived);
                    outputMut.unlock();
                }

                FILE* file = fopen(pszName, "wb");
                fwrite(pszDataBuffer, sizeof(char), sz[0], file);
                fclose(file);

                outputMut.lock();
                printf("\rProgress: %i%% [", percent);
                fwrite(dots, 1, 10, stdout);
                printf("]\n");
                outputMut.unlock();

                // auto open
                system(pszName);

                // 
                // Close the connection 
                // 
                if (SOCKET_ERROR == closesocket(ClientSocket))
                {
                    outputMut.lock();
                    wprintf(L"=CRITICAL= | closesocket() call failed w/socket = [0x%I64X]. WSAGetLastError=[%d]\n", (ULONG64)LocalSocket, WSAGetLastError());
                    outputMut.unlock();
                    ulRetCode = CXN_ERROR;
                }
                else
                {
                    // 
                    // Make the connection invalid regardless 
                    // 
                    ClientSocket = INVALID_SOCKET;
                }
            }
        }
    }

    if (INVALID_SOCKET != ClientSocket)
    {
        closesocket(ClientSocket);
        ClientSocket = INVALID_SOCKET;
    }

    if (INVALID_SOCKET != LocalSocket)
    {
        closesocket(LocalSocket);
        LocalSocket = INVALID_SOCKET;
    }

    if (NULL != lpCSAddrInfo)
    {
        //HeapFree(GetProcessHeap(), 0, lpCSAddrInfo);
        free(lpCSAddrInfo);
        lpCSAddrInfo = NULL;
    }
    if (NULL != pszInstanceName)
    {
        //HeapFree(GetProcessHeap(), 0, pszInstanceName);
        free(pszInstanceName);
        pszInstanceName = NULL;
    }

    if (NULL != pszDataBuffer)
    {
        //HeapFree(GetProcessHeap(), 0, pszDataBuffer);
        free(pszDataBuffer);
        pszDataBuffer = NULL;
    }

    return(ulRetCode);
}
