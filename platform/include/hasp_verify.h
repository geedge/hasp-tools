#ifndef _HASP_VERIFY_H
#define _HASP_VERIFY_H

#ifdef __cpluscplus
extern "C"
{
#endif

#include <stdint.h>

void hasp_verify(uint64_t feature_id, uint64_t interval_s);

#ifdef __cpluscplus
}
#endif

#endif
