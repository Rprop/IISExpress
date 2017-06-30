/********************************************************************
	Created:	2016/12/06  20:38
	Filename: 	IISExpress.hpp
	Author:		rrrfff
	Url:	    http://blog.csdn.net/rrrfff
*********************************************************************/
#include "IISExpress.h"
#include <RLib_StringConv.h>
#include <RLib_StringHelper.h>
#include <RLib_HttpUtility.h>
#include <RLib_Uri.h>
#include <RLib_Native.h>
//#include <httpserv.h>
#define ResponseWrite(a)  context->Client->Send(a, static_cast<int>(sizeof(a) - sizeof(a[0])))
#define BinaryWrite(a, b) context->Client->Send(a, static_cast<int>(b))
#define IIS_VERSION       "RLib-IISExpress/1.0"

//-------------------------------------------------------------------------

IISExpress::IISExpress()
{
	this->IsAborted = NULL;
	this->IpAddress = INADDR_ANY;
	this->Port      = 80;

	// relative path
	this->RootDirectory[0] = _T('\0');
}

//-------------------------------------------------------------------------

bool IISExpress::SatisfiesPrecondition()
{
	this->Listener = new System::Net::Sockets;
	if (!this->Listener || this->Listener->GetLastException()->HResult != STATUS_SUCCESS) {
		return false;
	} //if

	if (this->Listener->Bind(this->IpAddress, _byteswap_ushort(this->Port)) == SOCKET_ERROR) {
		return false;
	} //if

	if (this->Listener->Listen() == SOCKET_ERROR) {
		return false;
	} //if

	return true;
}

//-------------------------------------------------------------------------

bool IISExpress::Start()
{
	HttpContext *context = NULL;
	while ((context = new HttpContext(this)) != NULL) {
		int addrlen = sizeof(context->Endpoint);
		context->Client = this->Listener->Accept(&context->Endpoint, &addrlen);
		if (context->Client != NULL) {
			if (context->OnBeginRequest(this->TaskProvider)) context = NULL;
		} else {
			break;
		} //if
		if (this->IsAborted != NULL && this->IsAborted(this)) break;
	}
	
	RLIB_Delete(context);
	return true;
}

//-------------------------------------------------------------------------

void IISExpress::AssociateWithThreadPool(ThreadPool *pool)
{
	this->TaskProvider = pool;
}

//-------------------------------------------------------------------------

LPCSTR HttpContext::GetQueryString(LPCSTR pname, intptr_t lname, LPSTR pout, intptr_t nsize)
{
	pout[0] = '\0';

	const char *pstr  = strchr(this->buffer, ' ');
	const char *xpstr = pstr ? strchr(pstr, '\n') : NULL;
	if (xpstr) {
		while ((pstr = Utility::memstr(pstr, xpstr - pstr, pname, lname)) != NULL) {
			if (*(pstr - 1) != '&' && *(pstr - 1) != ' ') {
				pstr += lname;
				continue;
			} //if

			pstr += lname;
			if (*pstr != '=') continue;

			pstr += RLIB_COUNTOF_STR("=");
			const char *pend = strchr(pstr, '&');
			if (pend == nullptr) {
				pend = xpstr;
			} //if
			if ((pend - pstr + 1) <= nsize) {
				memcpy(pout, pstr, static_cast<size_t>(pend - pstr));
				pout[pend - pstr] = '\0';
				break;
			} //if
			trace(!"overflow");
			break;
		}
	} //if

	return pout;
}

//-------------------------------------------------------------------------

LPCSTR HttpContext::GetRequestVariables(LPCSTR pname, intptr_t lname, LPSTR pout, intptr_t nsize)
{
	pout[0] = '\0';

	const char *pstr = this->buffer;
	while ((pstr = Utility::stristr(pstr, pname)) != nullptr) {
		if (pstr != this->buffer && *(pstr - 1) != '\n') {
			pstr += lname;
			continue;
		} //if

		pstr += lname;
		if (*pstr != ':') continue;

		pstr += RLIB_COUNTOF_STR(": ");

		const char *pend = strchr(pstr, '\n');
		if (pend != nullptr) {
			if (*(pend - 1) == '\r') --pend;
			if ((pend - pstr + 1) <= nsize) {
				memcpy(pout, pstr, static_cast<size_t>(pend - pstr));
				pout[pend - pstr] = '\0';
				break;
			} //if
			trace(!"overflow");
			break;
		} //if
	}

	return pout;
}

//-------------------------------------------------------------------------

bool HttpContext::OnBeginRequest(ThreadPool *pool)
{
	return pool->AddTask<HttpContext *>([](HttpContext *context) {
		// stack buffer
		constexpr int size = RLIB_DEFAULT_MAX_BUFFER_SIZE;
		char buffer[size];

		// associate
		context->buffer    = buffer;
		context->totalsize = size;
		if (context->OnReceiveHttpHeaders()) {
			if (context->OnParseHttpRequest()) {
				context->OnExecuteRequestHandler();			
			} //if		
		} //if
		delete context;
	}, this);
}

//-------------------------------------------------------------------------

static String __format_size(long double size)
{
	String StrResult(16);
	if (size > 1024 * 1024 * 1024) {
		StrResult.copyf(_T("%.2LfG"), size / (1024 * 1024 * 1024));
	} else if (size > 1024 * 1024) {
		StrResult.copyf(_T("%.2LfM"), size / (1024 * 1024));
	} else if (size > 1024) {
		StrResult.copyf(_T("%ldkb"), long(size / 1024));
	} else {
		StrResult.copyf(_T("%ldb"), long(size));
	} //if
	return StrResult;
}

//-------------------------------------------------------------------------

static intptr_t __calc_special_characters(LPCTSTR lptext)
{
	// \u2E80-\uFE4F
	intptr_t count = 0;
	while (lptext[0] != _T('\0')) {
		if (lptext[0] >= _T('\u2E80') && lptext[0] <= _T('\uFE4F')) ++count;
		++lptext;
	}
	return count;
}

//-------------------------------------------------------------------------

static LPCSTR __format_utc_filetime(_In_ LARGE_INTEGER &vt, _Out_ CHAR GMT[32])
{
	TIME_FIELDS tf;
	RtlTimeToTimeFields(&vt, &tf);

	LPCSTR _ws = ("SunMonTueWedThuFriSat");
	LPCSTR _ms = ("JanFebMarAprMayJunJulAugSepOctNovDec");

	memcpy(&GMT[0], &_ws[tf.Weekday * 3], sizeof(CHAR) * 3);
	sprintf_s(&GMT[3], 32 - 3, ", %.2d %.3s %d %.2d:%.2d:%.2d GMT",
			  tf.Day, &_ms[(tf.Month - 1) * 3], tf.Year, tf.Hour, tf.Minute, tf.Second);
	return GMT;
}

//-------------------------------------------------------------------------

static LONGLONG __resolve_if_modified_since(HttpContext *context)
{
	LARGE_INTEGER sv = { 0 };
	char since[32];
	context->GetRequestVariables(RLIB_STR_LEN("If-Modified-Since"), RLIB_BUFFER_SIZE(since));
	if (since[0] != '\0' && since[3] == ',' && since[11] == ' ' && since[19] == ':' && since[22] == ':') {
		LPCSTR _ws = ("SunMonTueWedThuFriSat");
		LPCSTR _ms = ("JanFebMarAprMayJunJulAugSepOctNovDec");
		// Wed, 22 Jun 2011 06:40:43 GMT
		since[3] = since[11] = since[19] = since[22] = '\0';
		SYSTEMTIME st;
		st.wDayOfWeek = static_cast<WORD>((strstr(_ws, &since[0]) - _ws) / 3);
		if (st.wDayOfWeek >= 0 && st.wDayOfWeek <= 6) {
			st.wDay = static_cast<WORD>(strtol(&since[5], NULL, 10));
			if (st.wDay >= 1 && st.wDay <= 31) {
				st.wMonth = static_cast<WORD>((strstr(_ms, &since[8]) - _ms) / 3 + 1);
				if (st.wMonth >= 1 && st.wMonth <= 12) {
					st.wYear         = static_cast<WORD>(strtol(&since[12], NULL, 10));
					st.wHour         = static_cast<WORD>(strtol(&since[17], NULL, 10));
					st.wMinute       = static_cast<WORD>(strtol(&since[20], NULL, 10));
					st.wSecond       = static_cast<WORD>(strtol(&since[23], NULL, 10));
					st.wMilliseconds = 0;
					FILETIME ft;
					if (SystemTimeToFileTime(&st, &ft) != FALSE) {
						sv.LowPart  = ft.dwLowDateTime;
						sv.HighPart = static_cast<LONG>(ft.dwHighDateTime);
					} //if
				} //if
			} //if
		} //if
	} //if
	return sv.QuadPart;
}

//-------------------------------------------------------------------------

static bool __resolve_range(HttpContext *context, _Out_ LONGLONG &rstart, _Out_ LONGLONG &rend)
{
	char range[32];
	context->GetRequestVariables(RLIB_STR_LEN("Range"), RLIB_BUFFER_SIZE(range));
	// Range: bytes=0-704
	if (StringStartWith_4_A(range, "byte") && range[5] == '=') {
		LPCSTR sep = strstr(range, "-");
		if (sep != NULL && sep != range) {
			rstart = static_cast<LONGLONG>(strtoull(&range[6], NULL, 10)); // use strtoll?
			rend   = static_cast<LONGLONG>(strtoull(&sep[1], NULL, 10));
			return true;
		} //if
	} //if
//	rstart = rend = 0LL;
	return false;
}

//-------------------------------------------------------------------------

static void __list_directory_and_files(HttpContext *context, const String &dir)
{
	context->AddDefaultHeaders();
	context->SendSeverResponseHeader(200, "OK");
	ResponseWrite(_T("<?xml version=\"1.0\"?>\r\n"));
	ResponseWrite(_T("<html>\r\n<head>\r\n<title>Index of "));
	BinaryWrite(context->RequestURI, context->RequestURI.CanReadSize);
	ResponseWrite(_T("</title>\r\n</head>\r\n<body bgcolor=\"white\"><h1>Index of "));
	BinaryWrite(context->RequestURI, context->RequestURI.CanReadSize);
	ResponseWrite(_T("</h1><hr><pre><a href=\"../\">../</a>\r\n"));

	String delay_out;
	WIN32_FIND_DATA wfd;
	HANDLE hFindFile = FindFirstFile(dir + _R("*"), &wfd);
	while (FindNextFile(hFindFile, &wfd) == TRUE) {
		String strFile = StringReference(wfd.cFileName);
		if (strFile != _T("..")) {
			bool bIsDirectory = ((wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0);
			if (bIsDirectory) strFile += _R("/");

			FILETIME lt;
			FileTimeToLocalFileTime(&wfd.ftLastWriteTime, &lt);
			LARGE_INTEGER vt;
			vt.LowPart  = lt.dwLowDateTime;
			vt.HighPart = static_cast<LONG>(lt.dwHighDateTime);
			TIME_FIELDS tf;
			RtlTimeToTimeFields(&vt, &tf);
			String ftime;
			ftime.reserve(18, false).copyf(_T("%d-%.2d-%.2d %.2d-%.2d"),
										   tf.Year, tf.Month, tf.Day, tf.Hour, tf.Minute);

			String itemlink = _R("<a href=\"") + strFile + _R("\">") + strFile + _R("</a>");
			itemlink.padRight(64 + itemlink.Length - strFile.Length - __calc_special_characters(strFile));
			if (bIsDirectory) {
				BinaryWrite(itemlink, itemlink.CanReadSize);
				BinaryWrite(ftime, ftime.CanReadSize);
				ResponseWrite(_T("                   -\r\n"));
			} else {
				LARGE_INTEGER fsize;
				fsize.LowPart  = wfd.nFileSizeLow;
				fsize.HighPart = static_cast<LONG>(wfd.nFileSizeHigh);
				// delay output
				delay_out += itemlink;
				delay_out.appendf(_T("%s                   %s\r\n"),
								  ftime.GetConstData(),
								  __format_size(static_cast<long double>(fsize.QuadPart)).GetConstData());
			} //if
		} //if
	}
	FindClose(hFindFile);

	BinaryWrite(delay_out, delay_out.CanReadSize);
	ResponseWrite(_T("</pre><hr><a href=\"https://github.com/rrrfff/IISExpress\">") _T(IIS_VERSION) _T("</a> at "));
	String host(15 + 6 + 5);
	Sockets::Ipv4AddressToString(context->Host->IpAddress, host, 16);
	host.append(_R(" Port ") + UInt32(context->Host->Port).ToString());
	BinaryWrite(host, host.CanReadSize);
	ResponseWrite(_T("</body></html>"));
}

//-------------------------------------------------------------------------

static void __send_file(HttpContext *context, const String &filepath)
{
	FileFullAttributes file_info;
	ManagedObject<FileStream> file = File::Open(filepath, FileMode::OpenExist, FileAccess::Read, FileShare::All);
	if (file == nullptr || !file->GetFullAttributes(&file_info)) {
		return context->Output403Page(_T("/"), context->RequestURI,
									  _T("You don't have permission to access the URL on this server."));
	} //if
	
	if ((file_info.Attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
		file.Finalize();
		return context->Redirect(context->RequestURI + _R("/"));
	} //if

	LONGLONG since = __resolve_if_modified_since(context);
	if (since >= file_info.LastWriteTime.QuadPart) {
		return context->Output304Page();
	} //if

	LONGLONG rstart, rend;
	bool has_range  = __resolve_range(context, rstart, rend);
	if (has_range) {
		if (rend <= 0 || rend >= file_info.EndOfFile.QuadPart) rend = file_info.EndOfFile.QuadPart - 1;
		if (rend < rstart || rstart >= file_info.EndOfFile.QuadPart) {
			return context->Output416Page();
		} //if
	} //if

	LONGLONG filesize_all = file_info.EndOfFile.QuadPart;
	if (has_range) {
		file->SetPos64(rstart);
		filesize_all = rend - rstart + 1;
	} //if

	CHAR GMT[32];
	context->AddDefaultHeaders(false, false);
	
	context->Headers.Add("Last-Modified", __format_utc_filetime(file_info.LastWriteTime, GMT));
	context->AddMimeHeader(filepath);
	context->Headers.Add("Content-Length", RT2A(ToInt64(filesize_all).ToString()));
	if (has_range) {
		CHAR crange[64];
		sprintf_s(crange, RLIB_COUNTOF(crange), "bytes %llu-%llu/%llu", rstart, rend, file_info.EndOfFile.QuadPart);
		context->Headers.Add("Content-Range", crange);
		context->SendSeverResponseHeader(206, "Partial Content");
	} else {
		context->SendSeverResponseHeader(200, "OK");
	} //if
	
	if (filesize_all > 0) {
		char pchBuffer[RLIB_DEFAULT_MAX_BUFFER_SIZE * 2];
		while (filesize_all > 0 && !context->Host->IsAborted(context->Host)) {
			intptr_t retv = file->Read(pchBuffer, Utility::select_min(RLIB_COUNTOF(pchBuffer), static_cast<intptr_t>(filesize_all)));
			if (retv <= 0) break;			
			if (BinaryWrite(pchBuffer, retv) <= 0) break;
			filesize_all -= retv;
		}
	} //if
}

//-------------------------------------------------------------------------

void HttpContext::OnExecuteRequestHandler()
{
	String file = Path::ToDosPath(_R("C:") + Path::ToBackslash(this->RequestURI));
	if (file.Length >= 3) file.substring(3);

	String realpath = this->Host->RootDirectory + file;
	if (!File::Exist(realpath)) {
		return this->Output404Page(realpath, this->RequestURI);
	} //if

	if (realpath.EndsWith(_T('\\'))) {
		__list_directory_and_files(this, realpath);
	} else {
		__send_file(this, realpath.toLower());
	} //if
}

//-------------------------------------------------------------------------

bool HttpContext::OnParseHttpRequest()
{
	auto lpstart = &this->buffer[RLIB_COUNTOF_STR("GET ")];
	if (lpstart[0] == ' ') ++lpstart; // POST

	auto lpend = strstr(lpstart, " ");
	if (lpstart[0] != '/' || lpend == NULL) {
		this->Output400Page(_T("/"), _T("/"), _T("HTTP 400. Invalid request URI."));
		return false;
	} //if

	this->RequestURI.copy(lpstart, lpend - lpstart);
	this->RequestURI = Uri(_R("http://") + HttpUtility::UrlDecode(this->RequestURI)).GetAbsolutePath();
	return true;
}

//-------------------------------------------------------------------------

bool HttpContext::OnReceiveHttpHeaders()
{
	this->Client->SetReceiveTimeout(2000);

	int bufsize = this->totalsize - 1; // 缓冲区大小
	int  retval = 0;     // 已接收大小
	int  retcur = 0;     // 最近一次接收大小
	while ((retcur = this->Client->Recv(this->buffer + retval, bufsize - retval)) > 0) {
		// at this time, we only process GET and POST method
		bool bget  = StringStartWith_4_A(this->buffer, "GET ");
		bool bpost = StringStartWith_4_A(this->buffer, "POST");
		if (!bget && (!bpost || this->buffer[RLIB_COUNTOF_STR("POST")] != ' ')) return false; // invaild http request, drops it

		retval += retcur;
		this->buffer[retval] = '\0'; // makes null-terminated
		char *lpend = strstr(this->buffer, "\r\n\r\n");
		if (lpend != NULL && bget) {
			lpend[RLIB_COUNTOF_STR("\r\n\r\n")] = '\0'; // discards useless data
			retval = static_cast<int>(lpend + RLIB_COUNTOF_STR("\r\n\r\n") - this->buffer);
			break;
		} //if

		// no more spaces?
		if ((bufsize - retval) <= 0) {
			if (bget) {
				this->Output400Page(_T("/"), _T("/"), 
									_T("HTTP 400. The size of the request headers is too long."));
				return false;
			} //if
			break;
		} //if
	}
	this->received = retval;
	return true;
}

//-------------------------------------------------------------------------

void HttpContext::Redirect(LPCTSTR path)
{
	this->AddDefaultHeaders(false);
	this->Headers.Add("Location", RT2A(path));
	this->SendSeverResponseHeader(301, "Moved Permanently");
}

//-------------------------------------------------------------------------

void HttpContext::Output304Page()
{
	this->AddDefaultHeaders(false);
	this->SendSeverResponseHeader(304, "Not Modified");
}

//-------------------------------------------------------------------------

void HttpContext::Output400Page(LPCTSTR appname, LPCTSTR path, LPCTSTR error)
{
	this->AddDefaultHeaders();
	this->SendSeverResponseHeader(400, "Bad Request");
	this->OutputErrorPage(_T("Bad Request"), appname, _T("Bad Request"),
						  error, path);
}

//-------------------------------------------------------------------------

void HttpContext::Output403Page(LPCTSTR appname, LPCTSTR path, LPCTSTR error)
{
	this->AddDefaultHeaders();
	this->SendSeverResponseHeader(403, "Forbidden");
	this->OutputErrorPage(_T("403 Forbidden"), appname, _T("Forbidden"),
						  error, path);
}

//-------------------------------------------------------------------------

void HttpContext::Output404Page(LPCTSTR appname, LPCTSTR path)
{
	this->AddDefaultHeaders();
	this->SendSeverResponseHeader(404, "Not Found");
	this->OutputErrorPage(_T("The resource cannot be found."), appname,
						  _T("The resource cannot be found."),
						  _T("HTTP 404. The resource you are looking for (or one of its dependencies) could have been removed, had its name changed, or is temporarily unavailable. &nbsp;Please review the following URL and make sure that it is spelled correctly."),
						  path);
}

//-------------------------------------------------------------------------

void HttpContext::Output416Page()
{
	this->AddDefaultHeaders(false);
	this->SendSeverResponseHeader(416, "Requested Range Not Satisfiable");
}

//-------------------------------------------------------------------------

void HttpContext::OutputErrorPage(LPCTSTR title, LPCTSTR appname, 
								  LPCTSTR error, LPCTSTR detail, LPCTSTR path)
{
	const TCHAR master[] = _T(R"(<html>
    <head>
        <title>$TITLE</title>
        <style>
         body {font-family:"Verdana";font-weight:normal;font-size: .7em;color:black;} 
         p {font-family:"Verdana";font-weight:normal;color:black;margin-top: -5px}
         b {font-family:"Verdana";font-weight:bold;color:black;margin-top: -5px}
         H1 { font-family:"Verdana";font-weight:normal;font-size:18pt;color:red }
         H2 { font-family:"Verdana";font-weight:normal;font-size:14pt;color:maroon }
         pre {font-family:"Lucida Console";font-size: .9em}
         .marker {font-weight: bold; color: black;text-decoration: none;}
         .version {color: gray;}
         .error {margin-bottom: 10px;}
         .expandable { text-decoration:underline; font-weight:bold; color:navy; cursor:hand; }
        </style>
    </head>
    <body bgcolor="white">
            <span><H1>Server Error in '$APP' Application.<hr width=100% size=1 color=silver></H1>
            <h2> <i>$ERROR</i> </h2></span>
            <font face="Arial, Helvetica, Geneva, SunSans-Regular, sans-serif ">
            <b> Description: </b>$DETAIL
            <br><br>
            <b> Requested URL: </b>$PATH<br><br>
            <b> Source IP: </b>$IP<br><br>
    </body>
</html>)");

	String visitor(16 + 6);
	Sockets::Ipv4AddressToString(this->Endpoint.sin_addr.S_un.S_addr, visitor, 16);
	visitor.append(_R(":") + UInt32(_byteswap_ushort(this->Endpoint.sin_port)).ToString());
	String page = StringReference(master)
		.replace(_T("$TITLE"), title)
		.replace(_T("$APP"), appname)
		.replace(_T("$ERROR"), error)
		.replace(_T("$DETAIL"), detail)
		.replace(_T("$PATH"), path)
		.replace(_T("$IP"), visitor);

	this->Client->Send(page.GetConstData(), static_cast<int>(page.CanReadSize));
}

//-------------------------------------------------------------------------

void HttpContext::AddMimeHeader(const String &filename)
{
	const LPCVOID mime_mapping[][2] = { 
		{ _T(".htm"), "text/html" }, { _T(".html"), "text/html" },
		{ _T(".doc"), "application/msword" }, { _T(".docx"), "application/msword" },
		{ _T(".pdf"), "application/pdf" }, { _T(".ai"), "application/postscript" },
		{ _T(".eps"), "application/postscript" }, { _T(".tgz"), "application/x-compressed" },
		{ _T(".ppt"), "application/vnd.ms-powerpoint" },{ _T(".pptx"), "application/vnd.ms-powerpoint" },
		{ _T(".xls"), "application/vnd.ms-excel" }, { _T(".xlsx"), "application/vnd.ms-excel" },
		{ _T(".gz"), "application/x-gzip" }, { _T(".js"), "application/x-javascript" },
		{ _T(".swf"), "application/x-shockwave-flash" }, { _T(".zip"), "application/zip" },
		{ _T(".bmp"), "image/bmp" }, { _T(".gif"), "image/gif" },
		{ _T(".jpg"), "image/jpeg" }, { _T(".jpeg"), "image/jpeg" },
		{ _T(".ico"), "image/x-icon" }, { _T(".txt"), "text/plain" },
		{ _T(".c"), "text/plain" }, { _T(".cs"), "text/plain" },
		{ _T(".cpp"), "text/plain" }, { _T(".hpp"), "text/plain" },
		{ _T(".log"), "text/plain" }, { _T(".conf"), "text/plain" },
		{ _T(".asm"), "text/plain" },{ _T(".lua"), "text/plain" },
		{ _T(".ini"), "text/plain" },{ _T(".vbs"), "text/plain" },
		{ _T(".lnk"), "text/plain" },{ _T(".manifest"), "text/plain" },
		{ _T(".py"), "text/plain" },{ _T(".bat"), "text/plain" },
		{ _T(".cfg"), "text/plain" }, { _T(".md"), "text/plain" },
		{ _T(".psd"), "image/x-photoshop" },{ _T(".png"), "image/png" },
		{ _T(".xml"), "text/plain" }, { _T(".php"), "text/plain" },
		{ _T(".h"), "text/plain" }, { _T(".css"), "text/css" },
		{ _T(".mkv"), "video/x-matroska" },{ _T(".lrc"), "text/plain" },
		{ _T(".rmvb"), "application/vnd.rn-realmedia" },{ _T(".rm"), "application/vnd.rn-realmedia" },
		{ _T(".avi"), "video/x-msvideo" }, { _T(".flv"), "flv-application/octet-stream" },
		{ _T(".mp3"), "audio/mpeg" }, { _T(".m3u"), "audio/x-mpegurl" },
		{ _T(".mov"), "video/quicktime" }, { _T(".rar"), "application/x-rar-compressed" },
		{ _T(".mpg"), "video/mpeg" }, { _T(".mpeg"), "video/mpeg" }
	};
	for (auto &mime : mime_mapping) {
		if (filename.EndsWith(static_cast<LPCTSTR>(mime[0]))) {
			return this->Headers.Add("Content-Type", static_cast<LPCSTR>(mime[1]));
		} //if
	}
	return this->Headers.Add("Content-Type", "application/octet-stream");
}

//-------------------------------------------------------------------------

void HttpContext::AddDefaultHeaders(bool document /* = true */, bool date /* = true */)
{
	this->Headers.Add("Server", IIS_VERSION);
	this->Headers.Add("X-Powered-By", IIS_VERSION);
	this->Headers.Add("Connection", "close");
	if (date) {
		FILETIME sft;
		GetSystemTimeAsFileTime(&sft);
		LARGE_INTEGER lt;
		lt.LowPart  = sft.dwLowDateTime;
		lt.HighPart = static_cast<LONG>(sft.dwHighDateTime);
		CHAR GMT[32];
		this->Headers.Add("Date", __format_utc_filetime(lt, GMT));
	} //if
	if (document) {
		this->Headers.Add("Content-Type", "text/html; charset=utf-16");
	} else {
		this->Headers.Add("Accept-Ranges", "bytes");
	} //if
}

//-------------------------------------------------------------------------

void HttpContext::SendSeverResponseHeader(INT statusCode, LPCSTR statusDescription)
{
	char status[64];
	int length = sprintf_s(status, RLIB_COUNTOF(status),
						   "HTTP/1.1 %d %s\r\n", statusCode, statusDescription);
	this->Client->Send(status, length);
	this->Client->Send(this->Headers.ToByteArray(), static_cast<int>(this->Headers.GetByteArraySize()));
	this->Client->Send(RLIB_STR_LEN("\r\n\r\n"));
}