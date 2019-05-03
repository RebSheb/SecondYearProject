#include "HttpClass.h"

// Initializer function for WinSock.

void HttpClass::ReportError(const char* msg)
{
	printf("[!] - An error occured [0x%08x]: %s\n", WSAGetLastError(), msg);
	return;
}

int HttpClass::SendData(std::string data)
{
	if (!this->IsSocketValid())
	{
		this->ReportError("SendData reports invalid socket...");
		return SOCKET_ERROR;
	}

	if (data.size() > 0)
	{
		if (send(*this->thisSocket, data.c_str(), data.size(), 0) == SOCKET_ERROR)
		{
			this->ReportError("SendData send == SOCKET_ERROR...");
			return SOCKET_ERROR;
		}
	}
	return TRUE;
}

std::string HttpClass::ReceiveData(size_t bufferSize)
{
	if (!this->IsSocketValid())
	{
		this->ReportError("ReceiveData reports invalid socket...");
		return "400";
	}

	char* sRecv = new char[bufferSize];
	ZeroMemory(sRecv, bufferSize);

	if (recv(*this->thisSocket, sRecv, bufferSize, 0) == SOCKET_ERROR)
	{
		this->ReportError("RecieveData reports SOCKET_ERROR");
		return "400";
	}
	return std::string(sRecv);
}

HttpClass::HttpClass(std::string hostAddress, int port)
{
	this->SetHostAddress(hostAddress);
	this->hostaddr = hostAddress;
	this->SetHostPort(port);

	// Do some variable inits
	this->wsaData = (WSADATA*)malloc(sizeof(WSADATA));
	printf("Okpls\n");
	this->thisSocket = new SOCKET(INVALID_SOCKET);
	if (!this->InitializeWinSock())
	{
		this->ReportError("Failed to initialize HttpClass...");
		return;
	}
}

bool HttpClass::InitializeWinSock()
{
	/*if (!memcmp(this->wsaData, (const void*)0, sizeof(WSADATA)) == 0)
	{
		this->ReportError("Winsock already initialized...");
		return false;
	}*/
	if (this->isInit)
	{
		this->ReportError("This instance of HttpClass is already initialized...");
		return false;
	}
	ZeroMemory(&this->wsaData, sizeof(WSADATA));
	ZeroMemory(&this->hints, sizeof(addrinfo));

	int init_result = WSAStartup(MAKEWORD(2, 2), (WSADATA*)&this->wsaData);
	if (init_result != 0)
	{
		this->ReportError("WSAStartup failed...");
		return false;
	}

	this->hints.ai_family = AF_INET;
	this->hints.ai_socktype = SOCK_STREAM;
	this->hints.ai_protocol = IPPROTO_TCP;

	init_result = getaddrinfo(this->GetHostAddress().c_str(),
		std::to_string(this->GetHostPort()).c_str(),
		&this->hints, &this->result);

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

	this->isInit = true;
}

bool HttpClass::IsSocketValid()
{
	if (!(*this->thisSocket == INVALID_SOCKET))
	{
		return true;
	}
	return false;
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

std::string HttpClass::PostHTTP(std::string uri, std::string contentType, std::string postData)
{
	if (!this->IsSocketValid())
	{
		this->ReportError("PostHTTP reports a bad socket...");
		return "Bad socket";
	}

	std::string sRecvBuffer;

	std::string finalHeader;
	finalHeader = "POST " + uri + " HTTP/1.1\r\n";
	finalHeader += "Host: " + this->GetHostAddress() + ":" + std::to_string(this->GetHostPort()) + "\r\n";
	finalHeader += "Content-Type: " + contentType + "\r\n";
	finalHeader += "Content-Length: " + std::to_string(postData.size()) + "\r\n";
	finalHeader += "Accept-Charset: utf-8\r\n";
	finalHeader += "\r\n";
	finalHeader += postData + "\r\n";
	finalHeader += "\r\n";

	if (this->SendData(finalHeader) == SOCKET_ERROR)
	{
		this->ReportError("Error in HttpClass::PostHTTP()");
		return "";
	}
	sRecvBuffer = this->ReceiveData(1024);
	if (sRecvBuffer.c_str() == "400")
	{
		this->ReportError("Error in HttpClass::ReceiveData()");
		return "";
	}

	std::string retVal(sRecvBuffer);
	return retVal;
}



void HttpClass::Shutdown()
{
	if (this->IsSocketValid())
	{
		closesocket(*this->thisSocket);
	}
	WSACleanup();
	delete this->wsaData;
	delete this->ptr;
	delete this->result;
}


HttpClass::~HttpClass()
{
	this->Shutdown();
	// Cleanup WinSock items in here.
}
