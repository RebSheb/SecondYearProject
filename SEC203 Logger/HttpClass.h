#pragma once
#include <stdio.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <Windows.h>
#include <string>
#include <iostream>
#include <thread>

class HttpClass
{
private:
	SOCKET* thisSocket;
	WSADATA* wsaData;
	struct addrinfo* result = NULL, * ptr = NULL, *hints = NULL;


	std::string hostaddr = "127.0.0.1";
	int port = 2000;
	bool InitializeWinSock();
	bool IsSocketValid();
	void ReportError(const char *msg);

	int SendData(std::string data);

public:
	HttpClass(std::string hostAddress, int port);
		

	~HttpClass();


	std::string GetHostAddress();
	void SetHostAddress(std::string newHostAddress);
	int GetHostPort();
	void SetHostPort(int newPort);

	std::string PostHTTP(std::string uri, std::string contentType, std::string postData);

	void Shutdown();

};
