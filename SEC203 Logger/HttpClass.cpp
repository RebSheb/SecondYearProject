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
	if (!memcmp(this->wsaData, 0, sizeof(WSADATA)) == 0)
	{
		this->ReportError("Winsock already initialized...");
		return;
	}
	ZeroMemory(this->wsaData, sizeof(WSADATA));
	ZeroMemory(this->hints, sizeof(addrinfo));

	int init_result = WSAStartup(MAKEWORD(2, 2), this->wsaData);
	if (init_result != 0)
	{
		this->ReportError("WSAStartup failed...");
		return false;
	}

	this->hints->ai_family = AF_INET;
	this->hints->ai_socktype = SOCK_STREAM;
	this->hints->ai_protocol = IPPROTO_TCP;

	init_result = getaddrinfo(this->GetHostAddress().c_str(),
		std::to_string(this->GetHostPort()).c_str(),
		this->hints, &this->result);

	if (init_result != 0)
	{
		this->ReportError("getaddrinfo failed...");
		return false;
	}


	this->ptr = this->result;
	*this->thisSocket = socket(this->ptr->ai_family, this->ptr->ai_socktype, this->ptr->ai_protocol);

	if (*this->thisSocket == INVALID_SOCKET)
	{
		this->ReportError("Call to socket() failed\n");
		return false;
	}

	init_result = connect(*this->thisSocket, this->ptr->ai_addr,
		(int)this->ptr->ai_addrlen);
	
	if (init_result == SOCKET_ERROR)
	{
		std::string formatMessage("Failed to connect to " + this->GetHostAddress() +
			":" + std::to_string(this->GetHostPort()));
		this->ReportError(formatMessage.c_str());
		return false;
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

void HttpClass::Shutdown()
{
}


HttpClass::~HttpClass()
{
	// Cleanup WinSock items in here.
}
