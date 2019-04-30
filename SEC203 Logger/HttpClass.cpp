#include "HttpClass.h"

// Initializer function for WinSock.
void HttpClass::InitializeWinSock()
{
}

HttpClass::~HttpClass()
{
	// Cleanup WinSock items in here.
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
