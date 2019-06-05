/*
 * Copyright (c) 2013 YASUOKA Masahiko <yasuoka@yasuoka.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/param.h>
#include <sys/queue.h>

#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

struct memchunk {
	void			*caller;
	size_t			 size;
	int			 count;
	TAILQ_ENTRY(memchunk)	 next;
	u_char data[0];
};
TAILQ_HEAD(memchunk_head, memchunk);
static pthread_spinlock_t mleakdetect_lock;

struct memchunk_head	   mleakdetect_memchunk;
struct memchunk_head	   mleakdetect_stat;
static void		*(*mleakdetect_malloc)(size_t) = NULL;
static void		*(*mleakdetect_realloc)(void *, size_t) = NULL;
static void		 (*mleakdetect_free)(void *) = NULL;
static void		 (*mleakdetect_freezero)(void *, size_t) = NULL;
static int		   mleakdetect_initialized = 0; 
static int		   mleakdetect_malloc_count = 0; 
static int		   mleakdetect_free_count = 0; 
static int		   mleakdetect_unknown_free_count = 0; 
static int		   mleakdetect_stopped = 0;

static void	*malloc0(size_t, void *);
static void	*realloc0(void*, size_t, void *);
static int	 vasprintf0(char **, const char *, va_list, void *);
static void	 mleakdetect_initialize(void);
static void	 mleakdetect_atexit(void);
void		 mleakdetect_dump(int);

/* decls for the systems which doesn't have modern APIs. */
void		 freezero(void *, size_t);
void		*reallocarray(void *, size_t, size_t);
void		*recallocarray(void *, size_t, size_t, size_t);

/* dummy spin lock functions used if pthread is not linked */
int		 pthread_spin_init(pthread_spinlock_t *, int)
		    __attribute__((weak));
int		 pthread_spin_lock(pthread_spinlock_t *) __attribute__((weak));
int		 pthread_spin_unlock(pthread_spinlock_t *)
		    __attribute__((weak));

static void
mleakdetect_initialize(void)
{
	void	*libc_h;

	if ((libc_h = dlopen("libc.so", RTLD_NOW)) == NULL)
		return;

	TAILQ_INIT(&mleakdetect_memchunk);
	TAILQ_INIT(&mleakdetect_stat);

	mleakdetect_malloc   = dlsym(libc_h, "malloc");
	mleakdetect_realloc  = dlsym(libc_h, "realloc");
	mleakdetect_free     = dlsym(libc_h, "free");
	mleakdetect_freezero = dlsym(libc_h, "freezero");

	mleakdetect_initialized = 1;

	mleakdetect_stopped = 1;
	pthread_spin_init(&mleakdetect_lock, 0);
	mleakdetect_stopped = 0;

	atexit(mleakdetect_atexit);
}

void *
malloc(size_t size)
{
	return (malloc0(size, __builtin_return_address(0)));
}

static void *
malloc0(size_t size, void *caller)
{
	struct memchunk *m;

	if (mleakdetect_stopped)
		return (mleakdetect_malloc(size));
	if (mleakdetect_initialized == 0)
		mleakdetect_initialize();

	m = mleakdetect_malloc(offsetof(struct memchunk, data[size]));
	if (m == NULL)
		return (NULL);

	m->size = size;
	m->caller = caller;
	pthread_spin_lock(&mleakdetect_lock);
	mleakdetect_malloc_count++;
	TAILQ_INSERT_TAIL(&mleakdetect_memchunk, m, next);
	pthread_spin_unlock(&mleakdetect_lock);

	return (m->data);
}

void *
realloc(void *ptr, size_t size)
{
	return (realloc0(ptr, size, __builtin_return_address(0)));
}

void *
realloc0(void *ptr, size_t size, void *caller)
{
	void *r;
	struct memchunk *m;

	if (mleakdetect_initialized == 0)
		mleakdetect_initialize();

	if (ptr == NULL)
		return malloc0(size, caller);

	pthread_spin_lock(&mleakdetect_lock);
	TAILQ_FOREACH(m, &mleakdetect_memchunk, next) {
		if (m->data == ptr)
			break;
	}
	pthread_spin_unlock(&mleakdetect_lock);
	if (m == NULL)
		return (mleakdetect_realloc(ptr, size));
	r = malloc0(size, caller);
	if (r == NULL)
		return (r);
	memcpy(r, m->data, MIN(m->size, size));
	free(m->data);

	return (r);
}

void *
calloc(size_t nmemb, size_t size)
{
	size_t		 cnt;
	struct memchunk *m;
	void		*r;

	if (mleakdetect_stopped) {
		r = mleakdetect_malloc(size);
		memset(r, 0, size);
		return (r);
	}
	if (mleakdetect_initialized == 0)
		mleakdetect_initialize();
	
	cnt = (offsetof(struct memchunk, data[0]) / size) + 1;
	m = mleakdetect_malloc((nmemb + cnt) * size);
	if (m == NULL)
		return (NULL);
	memset(m, 0, (nmemb + cnt) * size);

	m->size = (nmemb + cnt) * size;
	m->caller = __builtin_return_address(0);
	pthread_spin_lock(&mleakdetect_lock);
	mleakdetect_malloc_count++;
	TAILQ_INSERT_TAIL(&mleakdetect_memchunk, m, next);
	pthread_spin_unlock(&mleakdetect_lock);

	return (m->data);
}

void *
reallocarray(void *ptr, size_t nmemb, size_t size)
{
	return (realloc0(ptr, nmemb * size, __builtin_return_address(0)));
}

void *
recallocarray(void *ptr, size_t oldnmemb, size_t nmemb, size_t size)
{
	void	*ret;

	ret = realloc0(ptr, nmemb * size, __builtin_return_address(0));

	if (ret != NULL && nmemb - oldnmemb > 0)
		memset(ret + oldnmemb * size, 0, (nmemb - oldnmemb) * size);

	return (ret);
}

char *
strdup(const char *str)
{
	void	*p;
	int	 lstr;

	lstr = strlen(str) + 1;
	p = malloc0(lstr, __builtin_return_address(0));
	strlcpy(p, str, lstr);

	return (p);
}

char *
strndup(const char *str, size_t maxlen)
{
	void	*p;
	int	 lstr = 0;

	while (str[lstr] != '\0' && lstr < maxlen)
		lstr++;
	lstr++;

	p = malloc0(lstr, __builtin_return_address(0));
	strlcpy(p, str, lstr);

	return (p);
}

int
vasprintf(char **ret, const char *format, va_list ap)
{
	return vasprintf0(ret, format, ap, __builtin_return_address(0));
}

int
asprintf(char **ret, const char *format, ...)
{
	va_list	 ap;
	int	 rv;

	va_start(ap, format);
	rv = vasprintf0(ret, format, ap, __builtin_return_address(0));
	va_end(ap);

	return (rv);
}

static int
vasprintf0(char **ret, const char *format, va_list ap, void *caller)
{
	char	*buf = NULL;
	int	 siz = 1024, len = 0;
	va_list	 ap0;

	for (;;) {
		buf = malloc0(siz, caller);
		va_copy(ap0, ap);
		len = vsnprintf(buf, siz, format, ap0);
		if (len != -1 && len < siz + 1)
			break;
		/* error or truncated */
		freezero(buf, siz);
		buf = NULL;
		if (len == -1)
			break;
		siz *= 2;
	}

	if (ret != NULL) {
		*ret = buf;
		buf = NULL;
	}
	if (buf != NULL)
		freezero(buf, siz);

	return (len);
}

void
free(void *mem)
{
	freezero(mem, 0);
}

void
freezero(void *mem, size_t size)
{
	struct memchunk	*m, *mt;

	if (mleakdetect_stopped) {
		if (mleakdetect_freezero != NULL && size > 0)
			mleakdetect_freezero(mem, size);
		else
			mleakdetect_free(mem);
		return;
	}
	if (mleakdetect_initialized == 0)
		mleakdetect_initialize();

	pthread_spin_lock(&mleakdetect_lock);
	TAILQ_FOREACH_SAFE(m, &mleakdetect_memchunk, next, mt) {
		if (m->data == mem) {
			TAILQ_REMOVE(&mleakdetect_memchunk, m, next);
			mleakdetect_free_count++;
			pthread_spin_unlock(&mleakdetect_lock);
			mleakdetect_free(m);
			return;
		}
	}
	mleakdetect_unknown_free_count++;
	pthread_spin_unlock(&mleakdetect_lock);
	if (mleakdetect_freezero != NULL && size > 0)
		mleakdetect_freezero(mem, size);
	else
		mleakdetect_free(mem);
}

static void
mleakdetect_atexit(void)
{
	mleakdetect_dump(STDERR_FILENO);
}

void
mleakdetect_dump(int fd)
{
	FILE		*out;
	struct memchunk	*m, *mt, *ms, *n, *l;
	Dl_info		 dlinfo;
	size_t		 total_leaks = 0;
	extern char	*__progname;

	mleakdetect_stopped = 1;
	/*
	 * dup fd before fdopen.  We would like to close FILE *out but
	 * need to keep opening the underlaying file descriptor.
	 */
	if ((fd = dup(fd)) < 0)
		return;
	if ((out = fdopen(dup(fd), "a+")) == NULL) {
		close(fd);
		return;
	}

	fprintf(out,
	    "\n"
	    "%s (pid=%d) mleakdetect report:\n"
	    "    malloc        %10d\n"
	    "    free          %10d\n"
	    "    unknown free  %10d\n"
	    "    unfreed       %10d (%6.2f%%)\n",
	    __progname, (int)getpid(),
	    mleakdetect_malloc_count, mleakdetect_free_count,
	    mleakdetect_unknown_free_count,
	    mleakdetect_malloc_count - mleakdetect_free_count,
	    (double)100.0 *
		(mleakdetect_malloc_count - mleakdetect_free_count)
		/ mleakdetect_malloc_count);

	TAILQ_FOREACH_SAFE(m, &mleakdetect_stat, next, mt) {
		TAILQ_REMOVE(&mleakdetect_stat, m, next);
		mleakdetect_free(m);
	}

	pthread_spin_lock(&mleakdetect_lock);
	TAILQ_FOREACH(m, &mleakdetect_memchunk, next) {
		TAILQ_FOREACH(ms, &mleakdetect_stat, next) {
			if (m->caller == ms->caller)
				break;
		}
		if (ms == NULL) {
			if ((ms = mleakdetect_malloc(sizeof(struct memchunk)))
			    == NULL) {
				fprintf(out, "malloc failed\n");
				goto on_error;
			}
			*ms = *m;
			ms->count = 0;
			TAILQ_INSERT_TAIL(&mleakdetect_stat, ms, next);
		} else
			ms->size += m->size;
		ms->count++;
		total_leaks += m->size;
	}
	pthread_spin_unlock(&mleakdetect_lock);

	/* bubble sort by size */
	l = NULL;
	m = TAILQ_FIRST(&mleakdetect_stat);
	n = (m != NULL)? TAILQ_NEXT(m, next) : NULL;
	while (n != l && m != l) {
		while (n != NULL && n != l) {
			if (m->size < n->size) {
				/* swap m and n */
				TAILQ_REMOVE(&mleakdetect_stat, m, next);
				TAILQ_INSERT_AFTER(&mleakdetect_stat, n, m,
				    next);
				n = TAILQ_NEXT(m, next);
			} else {
				m = n;
				n = TAILQ_NEXT(m, next);
			}
		}
		l = m;
		m = TAILQ_FIRST(&mleakdetect_stat);
		n = TAILQ_NEXT(m, next);
	}

	fprintf(out, "    total leaks   %10zu\n\n", total_leaks);
	fprintf(out, "memory leaks:\n");
	fprintf(out,
	    "    total bytes  count  avg. bytes  calling func(addr)\n");

	TAILQ_FOREACH(m, &mleakdetect_stat, next) {
		fprintf(out,
		    "    %11zu %6d %11d  ", m->size, m->count,
		    (int)(m->size / m->count));
		if (dladdr(m->caller, &dlinfo) != 0 &&
		    dlinfo.dli_sname != NULL && dlinfo.dli_sname[0] != '\0')
			fprintf(out, "%s+0x%x\n",
			    dlinfo.dli_sname,
			    (int)((caddr_t)m->caller -
				    (caddr_t)dlinfo.dli_saddr));
		else
			fprintf(out, "%p\n", m->caller);
	}
on_error:
	fclose(out);
	mleakdetect_stopped = 0;
}

/* dummy spin lock functions used if pthread is not linked */
int
pthread_spin_init(pthread_spinlock_t *lock, int pshared)
{
	return (0);
}

int
pthread_spin_lock(pthread_spinlock_t *lock)
{
	return (0);
}

int
pthread_spin_unlock(pthread_spinlock_t *lock)
{
	return (0);
}
