





#include <windows.h>
#include <sal.h>

#ifdef UNICODE

#undef UNICODE
#include <sql.h>
#include <sqlext.h>
#define UNICODE

#else
#include <sql.h>
#include <sqlext.h>
#endif