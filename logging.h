#pragma once

#ifdef _DEBUG
#define LOG_DEBUG(message) KdPrint((message))
#else
#define LOG_DEBUG(message) _noop
#endif