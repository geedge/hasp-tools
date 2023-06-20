#ifndef _HASP_SHM_H
#define _HASP_SHM_H

#ifdef __cpluscplus
extern "C"
{
#endif

struct hasp_shm;

struct hasp_shm *hasp_shm_new(const char *name);
void hasp_shm_free(struct hasp_shm *shm);

void hasp_shm_lock(struct hasp_shm *shm);
void hasp_shm_unlock(struct hasp_shm *shm);
void hasp_shm_write(struct hasp_shm *shm, char *data, int len);
void hasp_shm_read(struct hasp_shm *shm, char *buff, int size);

#ifdef __cpluscplus
}
#endif

#endif
