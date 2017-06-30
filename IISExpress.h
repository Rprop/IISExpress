/********************************************************************
	Created:	2016/12/06  20:38
	Filename: 	IISExpress.h
	Author:		rrrfff
	Url:	    http://blog.csdn.net/rrrfff
*********************************************************************/
#pragma once
#include <RLib_Object.h>
#include <RLib_Winsock.h>
#include <RLib_WebHeader.h>
#include <RLib_String.h>
#include <RLib_ThreadPool.h>
#include <RLib_Path.h>
#include <RLib_File.h>
using namespace System;
using namespace System::Net;
using namespace System::IO;
using namespace System::Threading;

//-------------------------------------------------------------------------

class HttpContext
{
public:
	ManagedObject<Sockets> Client;
	sockaddr_in            Endpoint;
	class IISExpress      *Host;
	WebHeaderCollection    Headers;
	String                 RequestURI;

public: // internal stack buffer
	char *buffer;
	int   totalsize, received;

public:
	bool OnBeginRequest(ThreadPool *pool);
	bool OnReceiveHttpHeaders();
	bool OnParseHttpRequest();
	void OnExecuteRequestHandler();

public:
	LPCSTR GetRequestVariables(LPCSTR pname, intptr_t lname,
							   LPSTR pout, intptr_t nsize);
	LPCSTR GetQueryString(LPCSTR pname, intptr_t lname,
						  LPSTR pout, intptr_t nsize);

public:
	void AddDefaultHeaders(bool document = true, bool date = true);
	void AddMimeHeader(const String &filename);
//	void AddMimeMapping(const String &extension, const String &MimeType);
	void SendSeverResponseHeader(INT statusCode, LPCSTR statusDescription);
	void Redirect(LPCTSTR path);
	void Output304Page();
	void Output400Page(LPCTSTR appname, LPCTSTR path, LPCTSTR error);
	void Output403Page(LPCTSTR appname, LPCTSTR path, LPCTSTR error);
	void Output404Page(LPCTSTR appname, LPCTSTR path);
	void Output416Page();
	void OutputErrorPage(LPCTSTR title, LPCTSTR appname, LPCTSTR error, LPCTSTR detail, LPCTSTR path);

public:
	HttpContext(class IISExpress *lphost) : Host(lphost) {}
	RLIB_DECLARE_DYNCREATE;

public:
	HttpContext(const HttpContext &) = delete;
	HttpContext(HttpContext &&) = delete;
	void operator = (const HttpContext &) = delete;
};

//-------------------------------------------------------------------------

class IISExpress
{
public:
	bool(*IsAborted)(IISExpress *);
	ThreadPool *TaskProvider;
	TCHAR       RootDirectory[RLIB_MAX_PATH];
	ULONG       IpAddress;
	USHORT      Port;
	
public:
	ManagedObject<Sockets> Listener;

public:
	IISExpress();
	RLIB_DECLARE_DYNCREATE;

public:
	void AssociateWithThreadPool(ThreadPool *pool);
	bool SatisfiesPrecondition();
	bool Start();

public:
	IISExpress(const IISExpress &) = delete;
	IISExpress(IISExpress &&) = delete;
	void operator = (const IISExpress &) = delete;
};