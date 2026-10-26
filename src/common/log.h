#pragma once

#include <string>

// Periodic performance stats (HOVER / DRAG / PF8 every 5 s). Off for release builds:
// each log write opens and closes twdll.log on the game thread.
#ifndef TWDLL_DEBUG_STATS
#define TWDLL_DEBUG_STATS 0
#endif

// Logs a formatted message to twdll.log
void Log(const char* format, ...);

// Logs a simple string
void Log(const std::string& message);
