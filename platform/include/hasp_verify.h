#ifndef _HASP_VERIFY_H
#define _HASP_VERIFY_H

#ifdef __cpluscplus
extern "C"
{
#endif

#include <stdint.h>

void hasp_monitor(uint64_t feature_id, uint64_t interval);
void hasp_verify(uint64_t feature_id);

#ifdef __cpluscplus
}
#endif

#endif
