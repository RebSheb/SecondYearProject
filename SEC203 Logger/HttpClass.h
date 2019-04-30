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
	std::string hostaddr;
	int port;

	void InitializeWinSock();

public:
	HttpClass(std::string hostAddress, int port):
		hostaddr(hostAddress), port(port), thisSocket(NULL){};

	~HttpClass();


	std::string GetHostAddress() { return this->hostaddr; }
	int GetHostPort() { return this->port; }


};
