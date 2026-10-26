#include "log.h"
#include <cstdio>
#include <cstdarg>
#include <fstream>
#include <mutex>
#include <windows.h>
#include <share.h>

static std::mutex g_log_mutex;
static const char* LOG_FILE = "twdll.log";
static bool g_log_fresh = true; // first write of this DLL load truncates the file

void Log(const char* format, ...) {
    std::lock_guard<std::mutex> lock(g_log_mutex);

    FILE* f = _fsopen(LOG_FILE, g_log_fresh ? "w" : "a", _SH_DENYNO);
    g_log_fresh = false;
    if (f) {
        va_list args;
        va_start(args, format);
        vfprintf(f, format, args);
        fprintf(f, "\n");
        va_end(args);
        fclose(f);
    }
}

void Log(const std::string& message) {
    Log("%s", message.c_str());
}
