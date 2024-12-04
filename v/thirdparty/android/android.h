#if defined(__ANDROID__)
	#include <android/log.h>

	
	#define V_ANDROID_LOG_STR_VALUE(arg) #arg
	#define V_ANDROID_LOG_NAME(tag_name) V_ANDROID_LOG_STR_VALUE(tag_name)

	#ifndef V_ANDROID_LOG_TAG
		#if defined(APPNAME)
			#define V_ANDROID_LOG_TAG APPNAME
		#else
			#define V_ANDROID_LOG_TAG "V"
		#endif
	#endif

	#define V_ANDROID_LOG_TAG_NAME V_ANDROID_LOG_NAME(V_ANDROID_LOG_TAG)

	int android_print(FILE *stream, const char *format, ...) {
		
		int res;
		va_list argptr;
		va_start(argptr, format);
		if (stream == stdout) {
			res = __android_log_vprint(ANDROID_LOG_INFO, V_ANDROID_LOG_TAG_NAME, format, argptr);
		} else {
			res = __android_log_vprint(ANDROID_LOG_ERROR, V_ANDROID_LOG_TAG_NAME, format, argptr);
		}
		return res;
	}
#endif
