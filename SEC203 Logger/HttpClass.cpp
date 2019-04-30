#include "HttpClass.h"

// Initializer function for WinSock.

void HttpClass::ReportError(const char* msg)
{
	printf("[!] - An error occured [0x%08x]: %s\n", WSAGetLastError(), msg);
	return;
}

HttpClass::HttpClass(std::string hostAddress, int port)
{
	this->SetHostAddress(hostAddress);
	this->SetHostPort(port);

	// Do some variable inits
	this->wsaData = new WSAData;
	this->thisSocket = new SOCKET(INVALID_SOCKET);
	if (!this->InitializeWinSock())
	{
		this->ReportError("Failed to initialize HttpClass...");
		return;
	}
}

bool HttpClass::InitializeWinSock()
{
	ZeroMemory(this->wsaData, sizeof(WSADATA));

	int init_result = WSAStartup(MAKEWORD(2, 2), this->wsaData);
	if (init_result != 0)
	{
		this->ReportError("WSAStartup failed...");
		return;
	}

}


// Returns the host address for the connection
// Or to be made connection.
std::string HttpClass::GetHostAddress() 
{ 
	return this->hostaddr;
}

void HttpClass::SetHostAddress(std::string newHostAddress)
{
	this->hostaddr = newHostAddress;
}

// Returns the connection port
int HttpClass::GetHostPort()
{
	return this->port; 
}

void HttpClass::SetHostPort(int newPort)
{
	if (newPort < 0)
		return;
	else if (newPort > 65565)
		return;

	this->port = newPort;
}


HttpClass::~HttpClass()
{
	// Cleanup WinSock items in here.
}
