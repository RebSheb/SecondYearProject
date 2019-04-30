#include <iostream>
#include <stdio.h>
#include <string>
#include <winsock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <thread>

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <iostream>
#include <fstream>
#include <vector>

#include <wincrypt.h>
#include <ntstatus.h>
#include <winnt.h>
#include <winternl.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ws2_32.lib") // WinSock for posting our file to server...

#define CRISTALLO_LEN 1024

LRESULT WINAPI MyKeyboardHook(int code, WPARAM wParam, LPARAM lParam);
void WriteToFile(DWORD vkCode, DWORD time, bool wasKeyUp);
static void initialize_hook_thread();
static void begin_file_transfer(std::string userName, std::string password);
bool hash_password(std::string pass, std::string* outPass);
bool authorize_user(SOCKET connectionSocket, std::string userName, std::string password);

DWORD lastKey = 0x0;
DWORD lastAction = 0x0;
DWORD* keyDuration = new DWORD[253];
std::string* stringStore = new std::string[253];
FILE* fp;


bool FirstEntry = true;
DWORD prevKey = 0x0;

std::string nonochars = "!\"£$%^&*()_+-={}[]:;@'~#<,>.?/|\\+";
// SCAN CODE, TIMESTAMP, DURATION
// SCAN CODE IS KEY PRESSED
// TIMESTAMP IS WHEN KEY PRESSED
// DURATION IS HOW LONG IT WAS PRESSED FOR

int main()
{
	printf("Keylog with timings for SEC203 Project\n");
	HANDLE threadHandle = CreateThread(0, 0,
		(LPTHREAD_START_ROUTINE)& initialize_hook_thread,
		0, 0, 0);

	if (threadHandle == INVALID_HANDLE_VALUE)
	{
		printf("Thread error...[GLE]: 0x%08x\n", GetLastError());
		return 0;
	}

	DWORD thread_status;
	std::string passAttempt = "";
	std::string userName = "";

	while (true)
	{
		if (GetExitCodeThread(threadHandle, &thread_status) == 0)
		{
			printf("An error has occured in GetExitCodeThread(), 0x%08x\n", GetLastError());
			TerminateThread(threadHandle, 0);
			exit(0);
		}

		if (thread_status != STILL_ACTIVE)
		{
			// MSDN recommends not using STILL_ACTIVE but this is an example program
			printf("Thread status is not STILL_ACTIVE, does this mean it has been terminated?\n");

		}

		userName = "";
		char* userBuff = new char[16];
		char* passBuff = new char[16];
		passAttempt = "";
		std::string hardCodedPass = "pass";

		/*printf("Please enter your username...: \n");
		scanf_s("%s", userBuff, sizeof(userBuff));
		getchar();
		printf("\nNow enter your password...: \n");
		scanf_s("%s", passBuff, sizeof(passBuff));*/

		std::cin >> userName;
		std::cin >> passAttempt;

		printf("\nEntered values [Username]: %s | [Password]: %s\n", userName.c_str(), passAttempt.c_str());


		//if (passAttempt.compare(hardCodedPass.c_str()) == 0) // Equal strings...
		//{
			//printf("Correct password...\n");
		TerminateThread(threadHandle, 100);
		printf("ThreadTerminated...\n");
		break;
		//return 0;
	//}
	}

	if (fp != NULL)
	{
		fclose(fp);
		printf("File wasn't closed... Closing...\n");
	}

	printf("\nBeginning file trasmission...\n");

	std::thread fileTransferThread(begin_file_transfer, userName, passAttempt);
	printf("Waiting on thread...\n");

	fileTransferThread.join(); // Blocks until file transfer complete...

	printf("File Transfer thread joined...\n");

}

static void initialize_hook_thread()
{
	HHOOK myKbHook = NULL;

	//printf("[Thread]: 0x%08x started...\n", GetCurrentThreadId());

	fopen_s(&fp, "data.csv", "w+");
	if (fp == NULL)
	{
		printf("An error occured opening data.txt :(\n");
		delete[] keyDuration;
		ExitThread(100);
		return;
	}

	fprintf_s(fp, "KeyCode,Timestamp,Duration,Latency\n");


	// Need to call SetWindowsHookEx with code of either 2 or 13.
	// * 13 is Lowlevel Keyboard hook
	// 2 is generic keyboard hook
	myKbHook = SetWindowsHookEx(WH_KEYBOARD_LL, MyKeyboardHook, NULL, 0);
	if (myKbHook == NULL)
	{
		printf("There was an error starting SetWindowsHookEx\n");
		printf("[GLE]: 0x%08x\n", GetLastError());
		fclose(fp);
		delete[] keyDuration;
		ExitThread(100);
	}


	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0))
	{

	}


	fclose(fp);
	UnhookWindowsHookEx(myKbHook);
	delete[] keyDuration;
	ExitThread(100);


}

void WriteToFile(DWORD vkCode, DWORD time, bool wasKeyUp)
{
	UINT mapKey = MapVirtualKey(vkCode, MAPVK_VK_TO_CHAR);
	if (mapKey == 0)
	{
		keyDuration[vkCode] = 0; // If it doesn't map to a character we don't care
		return;
	}

	switch (vkCode)
	{
	case VK_CONTROL:
	case VK_SHIFT:
	case VK_LSHIFT:
	case VK_RSHIFT:
	case VK_BACK:
	case VK_LWIN:
	case VK_RWIN:
	case VK_RETURN:
		//case VK_SPACE:
		return;

	default:
		break;

	}

	if (wasKeyUp == false) // Was it not a key up event?
	{
		if (nonochars.rfind((char)(char)mapKey) != std::string::npos) // is the character sent a punctuation character or anything?
			return;

		stringStore[vkCode] += ((char)(char)mapKey);
		stringStore[vkCode] += ',';
		//_itoa_s((unsigned long)time, itoaOutput, sizeof(itoaOutput), 10);
		stringStore[vkCode] += std::to_string(time);
		stringStore[vkCode] += ',';
		//printf("[KEYSTORE %d] : %s\n", vkCode, stringStore[vkCode].c_str());

	}

	else if (wasKeyUp)
	{
		if (nonochars.rfind((char)(char)mapKey) != std::string::npos)
			return;


		// Our key was released, we now have the duration time by doing
		// time - keyDuration[vkCode];
		//_itoa_s(time - keyDuration[vkCode], itoaOutput, sizeof(itoaOutput), 10);

		// DWELL TIME

		stringStore[vkCode] += std::to_string(time - keyDuration[vkCode]); // We add our final pieces of data to our buffer within the following "if"
		if (FirstEntry)
		{
			FirstEntry = false;
			stringStore[vkCode] += ",0\n";
			prevKey = vkCode;
		}
		else
		{
			// Time released is 
			// TIME RELEASED: keyDuration[vkCode] + (time - keyDuration[vkCode])

			// Latency is
			// TimeReleased - keyDuration[lastKey]
			stringStore[vkCode] += ',';
			if (vkCode != prevKey)
			{
				stringStore[vkCode] += std::to_string((keyDuration[vkCode] + (time - keyDuration[vkCode])) - keyDuration[prevKey]);
			}
			else
			{
				stringStore[vkCode] += std::to_string((keyDuration[vkCode] + (time - keyDuration[vkCode])) - keyDuration[vkCode]);
			}
			//stringStore[vkCode] += std::to_string(keyDuration[vkCode] + (time - keyDuration[vkCode]) - lastKey) ;
		}

		stringStore[vkCode] += '\n';
		//printf("[KEYSTORE %d] : %s\n", vkCode, stringStore[vkCode].c_str());
		fprintf_s(fp, stringStore[vkCode].c_str()); // Write it to the data.txt file.
		stringStore[vkCode].clear(); // Empty out our string buffer for a new character at that location.
		//stringStore[vkCode].em
		//stringStore[vkCode] = "";

	}

}


LRESULT WINAPI MyKeyboardHook( int code,  WPARAM wParam,  LPARAM lParam)
{
	// Type cast WPARAM to tagKBDLLHOOKSTRUCT as it containers a pointer to this

	if (code < 0)
		return CallNextHookEx(NULL, code, wParam, lParam);


	// We need to typecast lParam to a KBDLL struct, lParam contains a pointer to this
	tagKBDLLHOOKSTRUCT kbHook = *(tagKBDLLHOOKSTRUCT*)lParam;

	switch (wParam) // wParam is the Window Message.
	{
	case WM_SYSKEYUP:
	{
		break;
	}

	case WM_SYSKEYDOWN:
	{
		break;
	}

	case WM_KEYUP:
	{
		//printf("[KEYUP]: %x released...\n", kbHook.vkCode);
		//printf("%ul\n", kbHook.time);//, GetTickCount());
		WriteToFile(kbHook.vkCode, kbHook.time, true);
		lastAction = WM_KEYUP;
		prevKey = kbHook.vkCode;
		break;
	}

	case WM_KEYDOWN:
	{
		if (lastAction == WM_KEYDOWN && lastKey == kbHook.vkCode)
		{
			break;
		}

		lastKey = kbHook.vkCode;
		lastAction = WM_KEYDOWN;
		keyDuration[kbHook.vkCode] = kbHook.time;
		//printf("[KEYDOWN]: %c pressed...\n", kbHook.vkCode);
		//printf("%ul\n", kbHook.time);//, GetTickCount());
		WriteToFile(kbHook.vkCode, kbHook.time, false);
		break;
	}

	default:
	{
		break;
	}
	}

	return CallNextHookEx(NULL, code, wParam, lParam); // We have to call the next hook in sequence.
}


bool hash_password(std::string password,  std::string * outPassword)
{
	NTSTATUS Status;
	BCRYPT_ALG_HANDLE AlgHandle = NULL;
	BCRYPT_HASH_HANDLE HashHandle = NULL;

	PBYTE Hash = NULL;
	DWORD HashLength = 0;
	DWORD ResultLength = 0;
	std::vector<unsigned char> hash;

	if (outPassword == nullptr)
	{
		printf("OutPassword == nullptr\n");
		outPassword = new std::string();
	}

	Status = BCryptOpenAlgorithmProvider(&AlgHandle, BCRYPT_SHA256_ALGORITHM,
		NULL, BCRYPT_HASH_REUSABLE_FLAG);
	if (!NT_SUCCESS(Status))
	{
		printf("Error opening CryptoAlgorithmProvider\n");
		return false;
	}

	Status = BCryptGetProperty(AlgHandle, BCRYPT_HASH_LENGTH, (PBYTE)& HashLength, sizeof(HashLength), &ResultLength, 0);
	if (!NT_SUCCESS(Status))
	{
		printf("Failure to get BCryptProperty\n");
		return false;
	}
	hash.resize(HashLength);


	Hash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, HashLength);
	if (Hash == NULL)
	{
		//Status = STATUS_NO_MEMORY;
		printf("No memory for HeapAllocation for Hash\n");
		return false;
	}

	Status = BCryptCreateHash(AlgHandle, &HashHandle, NULL, 0, NULL, 0, 0);
	if (!NT_SUCCESS(Status))
	{
		printf("Failure to CryptCreateHash\n");
		return false;
	}

	Status = BCryptHashData(HashHandle,
		(PBYTE)password.c_str(), password.size(), 0);
	if (!NT_SUCCESS(Status))
	{
		printf("Failure to BCryptHashData\n");
		return false;
	}

	Status = BCryptFinishHash(HashHandle, hash.data(), HashLength, 0);
	if (!NT_SUCCESS(Status))
	{
		printf("Failure to BCryptFinishHash\n");
		return false;
	}

	HeapFree(GetProcessHeap(), 0, Hash);
	BCryptDestroyHash(HashHandle);
	BCryptCloseAlgorithmProvider(AlgHandle, 0);
	std::string hashPass(hash.begin(), hash.end());

	outPassword->clear();
	outPassword->assign(hashPass.c_str());
	printf("[PASSWORD]: %s\n", outPassword->c_str());
	return true;
}

bool authorize_user(SOCKET *connectionSocket, std::string userName, std::string password)
{
	if (connectionSocket == nullptr || *connectionSocket == INVALID_SOCKET)
	{
		printf("Cannot authorize user... Connection socket is bad.\n");
		return false;
	}
	const char* httpHeader;

	httpHeader = {
		"POST /user/login HTTP/1.1\r\n"
		"Host: 192.168.0.140:5000\r\n"
		"User-Agent: Mozilla Firefox/4.0\r\n"
		"Content-Length: %d\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n"
		"Accept-Charset: utf-8\r\n\r\n"
	};

	const char* postHeader;
	postHeader = { "username=%s&password=%s\r\n\r\n" };

	//


	char sHeader[sizeof(httpHeader) + 100];
	char* sData = new char[256];
	char sRecv[256];

	ZeroMemory(sHeader, sizeof(sHeader));
	ZeroMemory(sData, sizeof(sData));
	ZeroMemory(sRecv, sizeof(sRecv));

	std::string postData;
	postData = "username=" + userName;
	postData += "&passHash=" + password;
	int dataSize = postData.size();

	std::string header;
	header = "POST /user/create HTTP/1.1\r\n";
	header += "Host: 192.168.0.140:5000\r\n";
	header += "Content-Type: application/x-www-form-urlencoded\r\n";
	header += "Content-Length: " + std::to_string(dataSize) + "\r\n";
	header += "Accept-Charset: utf-8\r\n";
	header += "\r\n";
	header += postData + "\r\n";
	header += "\r\n";


	//printf("[DataLen]: %i\n[Header Len]: %i\n", dataSize, header.size());
	//printf("[HEADER]:\n%s\n", header.c_str());
	//printf("[POSTDATA]: %s\n", postData.c_str());
	if (header.size() > 0)
	{
		if (send(*connectionSocket, header.c_str(), header.size(), 0) != SOCKET_ERROR)
		{
			if (recv(*connectionSocket, sRecv, sizeof(sRecv), 0) != SOCKET_ERROR)
			{
				MessageBoxA(NULL, sRecv, 0, 0);
				printf("%s\n", sRecv);
				
			}
			else
			{
				printf("Failure to receive information from the server...\n");
				delete[] sData;
				return false;
			}
		}
		else
		{
			printf("Failure to send information to the server...\n");
			delete[] sData;
			return false;
		}
	}
	else
	{
		printf("Something went wrong with assigning the header?\n");
		delete[] sData;
		return false;
	}

	return false;
}


static void begin_file_transfer(std::string userName, std::string password)
{

	std::string outPass;
	if(!hash_password(password, &outPass))
	{
		printf("Something went wrong in hashing password...\n");
		return;
	}

	WSADATA* wsaData = new WSADATA;
	struct addrinfo* result = NULL,
		* ptr = NULL,
		hints;
	SOCKET ConnectionSocket = INVALID_SOCKET;

	ZeroMemory(wsaData, sizeof(WSADATA));
	int init_result = WSAStartup(MAKEWORD(2, 2), wsaData);
	if (init_result != 0)
	{
		printf("WSAStartup failed... File transfer cancelled!\n");
		return;
	}


	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	init_result = getaddrinfo("192.168.0.140", "5000", &hints, &result);
	if (init_result != 0)
	{
		printf("getaddrinfo failed!\n[GLE]: 0x%08x\n", WSAGetLastError());
		WSACleanup();
		return;
	}

	ptr = result;
	ConnectionSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
	if (ConnectionSocket == INVALID_SOCKET)
	{
		printf("ConnectionSocket is INVALID_SOCKET...\n[GLE]: 0x%08x\n", WSAGetLastError());
		WSACleanup();
		return;
	}

	init_result = connect(ConnectionSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
	if (init_result == SOCKET_ERROR)
	{
		printf("Failed to connect to that addres...\n[GLE]: 0x%08x\n", WSAGetLastError());
		closesocket(ConnectionSocket);
		ConnectionSocket = INVALID_SOCKET;
		WSACleanup();
		return;
	}

	if (!(authorize_user(ConnectionSocket, userName, outPass)))
	{
		printf("Bad authentication details...\n");
		closesocket(ConnectionSocket);
		ConnectionSocket = INVALID_SOCKET;
		WSACleanup();
		return;
	}

	/*FILE *sendFile = NULL;
	fopen_s(&sendFile, "data.csv", "r");
	if (sendFile == NULL)
	{
		printf("An error occured opening data.csv :(\n");
		ExitThread(100);
		return;
	}*/

	// LOGIN HERE

	

	std::ifstream sendFile("data.csv", std::ifstream::in);
	printf("0x%08x\n", (DWORD&)sendFile);
	if (sendFile)
	{
		sendFile.seekg(0, std::ifstream::beg);
		char* buffer = new char[1024];
		ZeroMemory(buffer, 1024);

		while (!sendFile.eof()) // -1 to accomodate for \0
		{
			sendFile.read(buffer, (1024 - 1));
			//printf("[Buffer]: %s\n", buffer);
			buffer[1023] = '\0';
			init_result = send(ConnectionSocket, buffer, 1024, 0);
			if (init_result == SOCKET_ERROR)
			{
				printf("Send failed: 0x%08x\n", WSAGetLastError());
				closesocket(ConnectionSocket);
				WSACleanup();
				return;
			}
			//printf("%s\n", buffer);
			ZeroMemory(buffer, 1024);
			printf("Sent 1024 bytes...\n");
		}

		delete[] buffer;
	}
	else
	{
		printf("SendFile is bad...\n");
		closesocket(ConnectionSocket);
		WSACleanup();
	}

	sendFile.close();
	closesocket(ConnectionSocket);
	WSACleanup();
}