#ifndef __SPINLOCK_H
#define __SPINLOCK_H

static inline int testandset(volatile int *spinlock)
{
	  int ret;
	
	  __asm__ __volatile__("xchgl %0, %1"
			       : "=r"(ret), "=m"(*spinlock)
			       : "0"(1), "m"(*spinlock));
	
	  return ret;
}

inline void spinlock_lock(volatile int * spinlock)
{
	  while (testandset(spinlock))
#if 0
		yield();
#else
		;
#endif
}

inline void spinlock_unlock(volatile int * spinlock)
{
#ifndef RELEASE
	  *spinlock = 0;
#else
	  RELEASE(spinlock);
#endif
}

#endif
