#include <iostream>
#include <stdio.h>
#include <string>
#include <winsock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <thread>

#include <windows.h>

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

#define API_HOST "192.168.0.196"

LRESULT WINAPI MyKeyboardHook(int code, WPARAM wParam, LPARAM lParam);
void WriteToFile(DWORD vkCode, DWORD time, bool wasKeyUp);
static void initialize_hook_thread();
static void begin_file_transfer(std::string userName, std::string password);
bool hash_password(std::string pass, std::string* outPass);
bool authorize_user(SOCKET *connectionSocket, std::string userName, std::string password);
std::string readWholeFile();

DWORD lastKey = 0x0;
DWORD lastAction = 0x0;
DWORD* keyDuration = new DWORD[253];
std::string* stringStore = new std::string[253];
std::vector<std::string> bigVectors;
//FILE* fp;
std::fstream *fp;


bool FirstEntry = true;
DWORD prevKey = 0x0;

std::string nonochars = "!\"�$%^&*()_+-={}[]:;@'~#<,>.?/|\\+";
// SCAN CODE, TIMESTAMP, DURATION
// SCAN CODE IS KEY PRESSED
// TIMESTAMP IS WHEN KEY PRESSED
// DURATION IS HOW LONG IT WAS PRESSED FOR

int main()
{
	bool learnMode = false;
	printf("----------Keylog with timings for SEC203 Project----------\n");
	printf("ID\tDescription\n--\t-----------\n");
	printf("1)\tLearn Mode\n");
	printf("2)\tLogin Mode\n");
	printf("3)\tExit\n");

	std::string choice;
	printf("Enter your choice: \n");
	std::cin >> choice;

	printf("[Choice]: %s\n", choice.c_str());
	int ichoice = std::atoi(choice.c_str());
	switch (ichoice)
	{
		case 1:
		{
			learnMode = true;
			break;
		}
		case 2:
		{
			learnMode = false;
			break;
		}
		case 3:
		{
			exit(0);
		}
		default:
			printf("Invalid ID entered\n");
			return 0;
	}

	HANDLE threadHandle = CreateThread(0, 0,
		(LPTHREAD_START_ROUTINE)& initialize_hook_thread,
		0, 0, 0);

	if (threadHandle == INVALID_HANDLE_VALUE)
	{
		printf("[!] - Thread error...[GLE]: 0x%08x\n", GetLastError());
		return 0;
	}

	DWORD thread_status;
	std::string passAttempt = "";
	std::string userName = "";

	while (true)
	{
		if (GetExitCodeThread(threadHandle, &thread_status) == 0)
		{
			printf("[!] - An error has occured in GetExitCodeThread(), 0x%08x\n", GetLastError());
			TerminateThread(threadHandle, 0);
			exit(0);
		}

		if (thread_status != 0x103)
		{
			// MSDN recommends not using STILL_ACTIVE but this is an example program
			printf("[?] - Thread status is not STILL_ACTIVE, does this mean it has been terminated?\n");

		}

		do
		{
			printf("Please enter your username & password, separated by the return key\n");
			Sleep(200);

			printf("[Username]: ");
			std::cin >> userName;
			printf("[Password]: ");
			std::cin >> passAttempt;

			printf("\n[*] - Entered values [Username]: %s | [Password]: %s\n", userName.c_str(), passAttempt.c_str());
			printf("[*] - Sleeping for 200ms to allow buffers to flush to files\n");
			Sleep(200);

			printf("\n[*] - Beginning file transmission...\n");

			std::thread fileTransferThread(begin_file_transfer, userName, passAttempt);
			printf("[*] - Waiting on thread...\n");
			fileTransferThread.join(); // Blocks until file transfer complete...

		} while (learnMode);
		TerminateThread(threadHandle, 100);
		printf("[*] - ThreadTerminated...\n");
		break;
		//return 0;
	//}
	}

	if (fp->is_open())
	{
		fp->close();
		printf("[*] - File wasn't closed... Closing...\n");
	}

	printf("\n[*] - Beginning file transmission...\n");

	std::thread fileTransferThread(begin_file_transfer, userName, passAttempt);
	printf("[*] - Waiting on thread...\n");

	fileTransferThread.join(); // Blocks until file transfer complete...

	printf("[+] - File Transfer thread joined...\n");


	system("pause");
}

static void initialize_hook_thread()
{
	HHOOK myKbHook = NULL;

	//printf("[Thread]: 0x%08x started...\n", GetCurrentThreadId());

	fp = new std::fstream("data.csv", std::fstream::in | std::fstream::out | std::fstream::trunc);
	if (!fp->is_open())
	{
		printf("[!] - An error occured opening data.csv :(\n");
		FILE *file;
		fopen_s(&file, "data.csv", "w");
		if (file == nullptr)
		{
			printf("[!] - Failure to create data.csv, closing thread...\n");

			delete[] keyDuration;
			ExitThread(100);
			return;
		}
		else
		{
			fclose(file);
			printf("[+] - Closed creating file handle, opening again with fstream...[It's still working Jay]\n");
			fp->open("data.csv", std::fstream::in| std::fstream::out | std::fstream::trunc);
		}
	}

	//fprintf_s(fp, "KeyCode,Timestamp,Duration,Latency\n");


	// Need to call SetWindowsHookEx with code of either 2 or 13.
	// * 13 is Lowlevel Keyboard hook
	// 2 is generic keyboard hook
	myKbHook = SetWindowsHookEx(WH_KEYBOARD_LL, MyKeyboardHook, NULL, 0);
	if (myKbHook == NULL)
	{
		printf("[!!] - There was an error starting SetWindowsHookEx\n");
		printf("[GLE]: 0x%08x\n", GetLastError());
		fp->close();
		delete[] keyDuration;
		ExitThread(100);
	}


	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0))
	{

	}


	fp->close();
	UnhookWindowsHookEx(myKbHook);
	delete[] keyDuration;
	ExitThread(100);


}

void WriteToFile(DWORD vkCode, DWORD time, bool wasKeyUp)
{
	if (!fp->is_open())
	{
		fp->open("data.csv", std::fstream::out);
	}
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
	{
		// When this is found, we will delete the last line in the file.
		//std::getline(fp, lineCount);
		// Seek to the end of the file - lastData_size; remove it.
		//int curPos = fp->tellp();
		//fp->seekp(curPos - lastData_size);
		// filep should be set to the end
		if (wasKeyUp)
		{
			if (bigVectors.size() == 0)
			{
				return;
			}
			bigVectors.erase(bigVectors.end()-1);
		}
		return;
	}
	case VK_LWIN:
	case VK_RWIN:
	case VK_RETURN:
		if (!fp->is_open())
		{
			fp->open("data.csv", std::fstream::in | std::fstream::out);
		}
		for (std::string x : bigVectors)
		{
			fp->write(x.c_str(), x.size());
		}

		bigVectors.clear();
		return;

	default:
		break;

	}

	if (wasKeyUp == false) // Was it not a key up event?
	{
		if (nonochars.rfind((char)(char)mapKey) != std::string::npos) // is the character sent a punctuation character or anything?
			return;

		stringStore[vkCode] += std::to_string(mapKey);
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
			stringStore[vkCode] += ",0";
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
		}

		stringStore[vkCode] += '\n';
		//printf("[KEYSTORE %d] : %s\n", vkCode, stringStore[vkCode].c_str());
		if (fp->is_open())
		{
			//printf("[DEBUG]: %s\n", stringStore[vkCode].c_str());
			//fp->write(stringStore[vkCode].c_str(), stringStore[vkCode].size()); // Write it to the data.txt file.
			bigVectors.push_back(stringStore[vkCode].c_str());
			stringStore[vkCode].clear(); // Empty out our string buffer for a new character at that location.
		}
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



	std::string retFile = readWholeFile();
	//printf("\n\n\n\n%s\n\n\n\n", retFile.c_str());

	std::string postData; // Construct 
	postData = "username=" + userName;
	postData += "&passHash=" + password;


	std::string header; // Construct our raw http header
	std::string body;

	body += "--------------dataentry\r\n";
	body += "Content-Disposition: form-data; name=\"username\"\r\n";
	body += "\r\n";

	body += userName + "\r\n";

	body += "--------------dataentry\r\n";
	body += "Content-Disposition: form-data; name=\"passHash\"\r\n";
	body += "\r\n";

	body += password + "\r\n";

	body += "--------------dataentry\r\n";
	body += "Content-Disposition: form-data; name=\"file\"; filename=\"file.csv\"\r\n";
	body += "Content-Type: text/csv\r\n";
	body += "\r\n";

	body += retFile + "\r\n";

	body += "--------------dataentry--\r\n";
	body += "\r\n";

	header = "POST /user/login HTTP/1.1\r\n";
	header += "Host: "+ std::string(API_HOST) + ":5000\r\n";
	header += "Content-Type: multipart/form-data; boundary=------------dataentry\r\n";
	header += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
	header += body;
	//header += "\r\n";




	

	//printf("[DataLen]: %i\n[Header Len]: %i\n", dataSize, header.size());
	printf("[HEADER]:\n%s\n\n\n\n", header.c_str());
	//printf("[POSTDATA]: %s\n", postData.c_str());
	if (header.size() > 0)
	{
		if (send(*connectionSocket, header.c_str(), header.size(), 0) != SOCKET_ERROR)
		{
			/*if (send(*connectionSocket, body.c_str(), body.size(), 0) == SOCKET_ERROR)
			{
				printf("Error in sending the content body\n");
				return false;
			}*/
			// Received HTTP response buffer.
			char bigbuff[1024];
			ZeroMemory(&bigbuff, sizeof(bigbuff));
			printf("Waiting for data from server\n");
			if (recv(*connectionSocket, bigbuff, sizeof(bigbuff), 0) != SOCKET_ERROR)
			{
				//MessageBoxA(NULL, sRecv, 0, 0);			
				std::string responseData(bigbuff);
				printf("%s\n", responseData.c_str());
				if (responseData.find("200") != std::string::npos)
				{
					printf("Successfully authorized user\n");
					return true;
				}
				else
				{
					printf("Error occured.\n[Response]: %s\n", responseData.c_str());
					return false;
				}
			}
			else
			{
				printf("Failure to receive information from the server...\n");
				return false;
			}
		}
		else
		{
			printf("Failure to send information to the server...\n");
			return false;
		}
	}
	else
	{
		printf("Something went wrong with assigning the header?\n");
		return false;
	}

	return false;
}


static void begin_file_transfer(std::string userName, std::string password)
{

	std::string outPass; // Hash our password
	if (!hash_password(password, &outPass))
	{
		printf("Something went wrong in hashing password...\n");
		return;
	}

#pragma region WinSock



	WSADATA* wsaData = new WSADATA;
	struct addrinfo* result = NULL,
		* ptr = NULL,
		hints;
	SOCKET ConnectionSocket = INVALID_SOCKET;

	ZeroMemory(wsaData, sizeof(wsaData));
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

	// Change the IP and port here accordingly
	init_result = getaddrinfo(API_HOST, "5000", &hints, &result);
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
		printf("Failed to connect to that address...\n[GLE]: 0x%08x\n", WSAGetLastError());
		closesocket(ConnectionSocket);
		ConnectionSocket = INVALID_SOCKET;
		WSACleanup();
		return;
	}
#pragma endregion



	if (!(authorize_user(&ConnectionSocket, userName, outPass)))
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

}

std::string readWholeFile()
{
	std::string wholeFile;
	fp->flush(); // Synchronize data to the file.
	std::ifstream sendFile("data.csv", std::ifstream::in);
	//printf("0x%08x\n", (DWORD&)sendFile);
	if (sendFile)
	{
		sendFile.seekg(0, std::ifstream::beg);
		char* buffer = new char[1024];
		ZeroMemory(buffer, 1024);

		while (!sendFile.eof())
		{
			sendFile.read(buffer, sizeof(buffer));
			//printf("[Buffer]: %s\n", buffer);
			wholeFile += buffer;

			//printf("%s\n", buffer);
			ZeroMemory(buffer, 1024);
		}

		delete[] buffer;
	}
	sendFile.close();
	return wholeFile;
}