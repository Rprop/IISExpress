#include <RLib_LibImport.h>
#include "IISExpress.h"
#include "IISExpress.hpp" // include once

//-------------------------------------------------------------------------

static volatile long stoping = FALSE;
static IISExpress server;
RLIB_STATIC({
	server.IsAborted = [](IISExpress *)->bool {
		return stoping != FALSE;
	};
});

//-------------------------------------------------------------------------

void main()
{
	ManagedObject<ThreadPool> pool = pool.construct();
	server.AssociateWithThreadPool(pool);

	server.Port      = static_cast<USHORT>(8080);
	server.IpAddress = 0U; // Sockets::Ipv4StringToAddress(_T("0.0.0.0"));
	StringCopyTo(Path::ToNtPath(AppBase::GetStartupPath()), server.RootDirectory);

	// begins to loop
	if (server.SatisfiesPrecondition()) {
		server.Start();
		server.Listener.Finalize();
	} //if
}