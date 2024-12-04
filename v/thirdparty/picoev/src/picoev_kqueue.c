

#include <errno.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>
#include "picoev.h"

#define EV_QUEUE_SZ 128

#define BACKEND_BUILD(next_fd, events)	\
  ((unsigned)((next_fd << 8) | (events & 0xff)))
#define BACKEND_GET_NEXT_FD(backend) ((int)(backend) >> 8)
#define BACKEND_GET_OLD_EVENTS(backend) ((int)(backend) & 0xff)

typedef struct picoev_loop_kqueue_st {
  picoev_loop loop;
  int kq;
  int changed_fds;
  struct kevent events[1024];
  struct kevent changelist[256];
} picoev_loop_kqueue;

picoev_globals picoev;

static int apply_pending_changes(picoev_loop_kqueue* loop, int apply_all)
{
#define SET(op, events)						\
  EV_SET(loop->changelist + cl_off++, loop->changed_fds,	\
	 (((events) & PICOEV_READ) != 0 ? EVFILT_READ : 0)	\
	 | (((events) & PICOEV_WRITE) != 0 ? EVFILT_WRITE : 0), \
	 (op), 0, 0, NULL)
  
  int cl_off = 0, nevents;
  
  while (loop->changed_fds != -1) {
    picoev_fd* changed = picoev.fds + loop->changed_fds;
    int old_events = BACKEND_GET_OLD_EVENTS(changed->_backend);
    if (changed->events != old_events) {
      if (old_events != 0) {
	SET(EV_DISABLE, old_events);
      }
      if (changed->events != 0) {
	SET(EV_ADD | EV_ENABLE, changed->events);
      }
      if ((size_t)cl_off + 1
	  >= sizeof(loop->changelist) / sizeof(loop->changelist[0])) {
	nevents = kevent(loop->kq, loop->changelist, cl_off, NULL, 0, NULL);
	assert(nevents == 0);
	cl_off = 0;
      }
    }
    loop->changed_fds = BACKEND_GET_NEXT_FD(changed->_backend);
    changed->_backend = -1;
  }
  
  if (apply_all && cl_off != 0) {
    nevents = kevent(loop->kq, loop->changelist, cl_off, NULL, 0, NULL);
    assert(nevents == 0);
    cl_off = 0;
  }
  
  return cl_off;
  
#undef SET
}

picoev_loop* picoev_create_loop(int max_timeout)
{
  picoev_loop_kqueue* loop;
  
 
  assert(PICOEV_IS_INITED);
  if ((loop = (picoev_loop_kqueue*)malloc(sizeof(picoev_loop_kqueue)))
      == NULL) {
    return NULL;
  }
  if (picoev_init_loop_internal(&loop->loop, max_timeout) != 0) {
    free(loop);
    return NULL;
  }
  
 
  if ((loop->kq = kqueue()) == -1) {
    picoev_deinit_loop_internal(&loop->loop);
    free(loop);
    return NULL;
  }
  loop->changed_fds = -1;
  
  loop->loop.now = time(NULL);
  return &loop->loop;
}

int picoev_destroy_loop(picoev_loop* _loop)
{
  picoev_loop_kqueue* loop = (picoev_loop_kqueue*)_loop;
  
  if (close(loop->kq) != 0) {
    return -1;
  }
  picoev_deinit_loop_internal(&loop->loop);
  free(loop);
  return 0;
}

int picoev_update_events_internal(picoev_loop* _loop, int fd, int events)
{
  picoev_loop_kqueue* loop = (picoev_loop_kqueue*)_loop;
  picoev_fd* target = picoev.fds + fd;
  
  assert(PICOEV_FD_BELONGS_TO_LOOP(&loop->loop, fd));
  
 
  if ((events & PICOEV_ADD) != 0) {
    target->_backend = -1;
  }
 
  if (events == PICOEV_DEL
      ? target->_backend == -1
      : (events & PICOEV_READWRITE) == target->events) {
    return 0;
  }
 
  if (target->_backend == -1) {
    target->_backend = BACKEND_BUILD(loop->changed_fds, target->events);
    loop->changed_fds = fd;
  }
 
  target->events = events & PICOEV_READWRITE;
 
  if ((events & PICOEV_DEL) != 0) {
    apply_pending_changes(loop, 1);
  }
  
  return 0;
}

int picoev_poll_once_internal(picoev_loop* _loop, int max_wait)
{
  picoev_loop_kqueue* loop = (picoev_loop_kqueue*)_loop;
  struct timespec ts;
  int cl_off = 0, nevents, i;
  
 
  cl_off = apply_pending_changes(loop, 0);
  
  ts.tv_sec = max_wait;
  ts.tv_nsec = 0;
  nevents = kevent(loop->kq, loop->changelist, cl_off, loop->events,
		   sizeof(loop->events) / sizeof(loop->events[0]), &ts);
  if (nevents == -1) {
   
    assert(errno == EACCES || errno == EFAULT || errno == EINTR);
    return -1;
  }
  for (i = 0; i < nevents; ++i) {
    struct kevent* event = loop->events + i;
    picoev_fd* target = picoev.fds + event->ident;
    assert((event->flags & EV_ERROR) == 0);
    if (loop->loop.loop_id == target->loop_id
	&& (event->filter & (EVFILT_READ | EVFILT_WRITE)) != 0) {
      int revents;
      switch (event->filter) {
      case EVFILT_READ:
	revents = PICOEV_READ;
	break;
      case EVFILT_WRITE:
	revents = PICOEV_WRITE;
	break;
      default:
	assert(0);
	revents = 0; 
	break;
      }
      (*target->callback)(&loop->loop, event->ident, revents, target->cb_arg);
    }
  }
  
  return 0;
}
