#ifndef _DECTMON_UTILS_H
#define _DECTMON_UTILS_H

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#define __init			__attribute__((constructor))
#define __exit			__attribute__((destructor))
#define __must_check		__attribute__((warn_unused_result))
#define __maybe_unused		__attribute__((unused))
#define __noreturn		__attribute__((__noreturn__))
#define __aligned(x)		__attribute__((aligned(x)))
#define __packed		__attribute__((packed))
#define __visible		__attribute__((visibility("default")))

#define BUG()			assert(0)

/* Force a compilation error if condition is true */
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#define BUILD_BUG_ON_ZERO(e) (sizeof(char[1 - 2 * !!(e)]) - 1)

#define __must_be_array(a) \
	BUILD_BUG_ON_ZERO(__builtin_types_compatible_p(typeof(a), typeof(&a[0])))

#define array_size(arr)		(sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))
#define field_sizeof(t, f)	(sizeof(((t *)NULL)->f))

#define div_round_up(n, d)	(((n) + (d) - 1) / (d))

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

#define max(x, y) ({				\
	typeof(x) _max1 = (x);			\
	typeof(y) _max2 = (y);			\
	(void) (&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2; })

static inline unsigned int fls(uint64_t v)
{
	unsigned int len = 0;

	while (v) {
		v >>= 1;
		len++;
	}
	return len;
}

#define ptrlist_init(head)				\
	do {						\
		*(head) = NULL;				\
	} while (0)

#define ptrlist_add_tail(new, head)			\
	do {						\
		typeof(new) *pprev;			\
		pprev = (head);				\
		while (*pprev != NULL)			\
			pprev = &(*pprev)->next;	\
		*pprev = new;				\
	} while (0)

#define ptrlist_dequeue_head(head)			\
	({						\
		typeof(*head) elem = *(head);		\
		if (elem != NULL)			\
			*(head) = elem->next;		\
		elem;					\
	})

#endif /* _DECTMON_UTILS_H */
