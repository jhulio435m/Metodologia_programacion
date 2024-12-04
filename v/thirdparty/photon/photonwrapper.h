#ifndef C_PHOTONWRAPPER_H_
#define C_PHOTONWRAPPER_H_

#include <sys/socket.h>


#ifdef __cplusplus

#include <fcntl.h>


#include <photon/thread/std-compat.h>
#include <photon/common/alog.h>
#include <photon/common/iovector.h>
#include <photon/fs/localfs.h>
#include <photon/net/socket.h>
#include <photon/net/basic_socket.h>
#include <photon/thread/workerpool.h>
#include <iostream>

extern "C" {


photon::WorkPool* work_pool;




#else
#endif

void* new_photon_work_pool(size_t);

void delete_photon_work_pool();

void init_photon_work_pool(size_t);


void photon_thread_create_and_migrate_to_work_pool(void* (* f)(void*), void* arg);

int photon_join_current_thread_into_workpool();
void photon_set_log_output_stdout();
void photon_set_log_output_stderr();
void photon_set_log_output_null();

int photon_init_default();
void photon_thread_create(void* (* f)(void*), void* arg);
void photon_sleep_s(int n);
void photon_sleep_ms(int n);

void* default_photon_thread_stack_alloc(void*, size_t size);
void default_photon_thread_stack_dealloc(void*, void* ptr, size_t size);
void set_photon_thread_stack_allocator(
    void* (*alloc_func)(void*, size_t),
    void (*dealloc_func)(void*, void*, size_t)
);

int photon_socket(int domain, int type, int protocol);
int photon_connect(int fd, const struct sockaddr *addr, socklen_t addrlen, uint64_t timeout);
int photon_accept(int fd, struct sockaddr *addr, socklen_t *addrlen, uint64_t timeout);
ssize_t photon_send(int fd, const void* buf, size_t len, int flags, uint64_t timeout);

ssize_t photon_recv(int fd, void* buf, size_t count, int flags, uint64_t timeout);


#ifdef __cplusplus
}
#endif


#endif