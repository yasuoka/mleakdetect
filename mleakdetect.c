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
#include <sys/tree.h>

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

struct memchunk {
	void			*caller;
	size_t			 size;
	int			 count;
	RB_ENTRY(memchunk)	 tree;
	TAILQ_ENTRY(memchunk)	 next;
	u_char data[0];
};
RB_HEAD(memchunk_tree, memchunk);
TAILQ_HEAD(memchunk_head, memchunk);
#define	MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))

static int memchunk_cmp(struct memchunk *, struct memchunk *);
RB_PROTOTYPE_STATIC(memchunk_tree, memchunk, tree, memchunk_cmp);

static pthread_spinlock_t mleakdetect_lock;

struct memchunk_tree	   mleakdetect_memchunk;
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
static void	*calloc0(size_t, size_t, void *);
static int	 vasprintf0(char **, const char *, va_list, void *);
static void	 mleakdetect_initialize(void);
static void	 mleakdetect_atexit(void);
void		 mleakdetect_dump(int);
/* from open_memstream.c */
static FILE	*mleakdetect_open_memstream(char **, size_t *, void *);

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

	RB_INIT(&mleakdetect_memchunk);
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
	RB_INSERT(memchunk_tree, &mleakdetect_memchunk, m);
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
	struct memchunk *m, *m0;

	if (mleakdetect_initialized == 0)
		mleakdetect_initialize();

	if (ptr == NULL)
		return malloc0(size, caller);

	m0 = (struct memchunk *)
	    ((caddr_t)ptr - offsetof(struct memchunk, data));

	pthread_spin_lock(&mleakdetect_lock);
	m = RB_FIND(memchunk_tree, &mleakdetect_memchunk, m0);
	pthread_spin_unlock(&mleakdetect_lock);
	if (m == NULL)
		return (mleakdetect_realloc(ptr, size));

	r = malloc0(size, caller);
	if (r == NULL)
		return (r);
	if (m != NULL) {
		memcpy(r, m->data, MINIMUM(m->size, size));
		free(m->data);
	}

	return (r);
}

void *
calloc0(size_t nmemb, size_t size, void *caller)
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

	m->size = nmemb * size;
	m->caller = __builtin_return_address(0);
	pthread_spin_lock(&mleakdetect_lock);
	mleakdetect_malloc_count++;
	RB_INSERT(memchunk_tree, &mleakdetect_memchunk, m);
	pthread_spin_unlock(&mleakdetect_lock);

	return (m->data);
}

void *
calloc(size_t nmemb, size_t size)
{
	return (calloc0(nmemb, size, __builtin_return_address(0)));
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

	if (ret != NULL && nmemb > oldnmemb)
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

FILE *
open_memstream(char **pbuf, size_t *psize)
{
	return (mleakdetect_open_memstream(pbuf, psize,
	    __builtin_return_address(0)));
}

void
free(void *mem)
{
	freezero(mem, 0);
}

void
freezero(void *mem, size_t size)
{
	struct memchunk	*m, *m0;

	if (mem == NULL)
		return;

	if (mleakdetect_stopped) {
		if (mleakdetect_freezero != NULL && size > 0)
			mleakdetect_freezero(mem, size);
		else
			mleakdetect_free(mem);
		return;
	}
	if (mleakdetect_initialized == 0)
		mleakdetect_initialize();

	m0 = (struct memchunk *)
	    ((caddr_t)mem - offsetof(struct memchunk, data));

	pthread_spin_lock(&mleakdetect_lock);
	m = RB_FIND(memchunk_tree, &mleakdetect_memchunk, m0);
	if (m != NULL) {
		RB_REMOVE(memchunk_tree, &mleakdetect_memchunk, m);
		mleakdetect_free_count++;
	} else
		mleakdetect_unknown_free_count++;
	pthread_spin_unlock(&mleakdetect_lock);

	if (m != NULL)
		mleakdetect_free(m);
	else if (mleakdetect_freezero != NULL && size > 0)
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
	struct memchunk	*m, *mt, *ms, *n, *l;
	Dl_info		 dlinfo;
	size_t		 total_leaks = 0;
	extern char	*__progname;

	mleakdetect_stopped = 1;

	dprintf(fd,
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
	RB_FOREACH(m, memchunk_tree, &mleakdetect_memchunk) {
		TAILQ_FOREACH(ms, &mleakdetect_stat, next) {
			if (m->caller == ms->caller)
				break;
		}
		if (ms == NULL) {
			if ((ms = mleakdetect_malloc(sizeof(struct memchunk)))
			    == NULL) {
				dprintf(fd, "malloc failed\n");
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

	dprintf(fd, "    total leaks   %10zu\n\n", total_leaks);
	dprintf(fd, "memory leaks:\n");
	dprintf(fd,
	    "    total bytes  count  avg. bytes  calling func(addr)\n");

	TAILQ_FOREACH(m, &mleakdetect_stat, next) {
		dprintf(fd,
		    "    %11zu %6d %11d  ", m->size, m->count,
		    (int)(m->size / m->count));
		if (dladdr(m->caller, &dlinfo) != 0 &&
		    dlinfo.dli_sname != NULL && dlinfo.dli_sname[0] != '\0')
			dprintf(fd, "%s+0x%x\n",
			    dlinfo.dli_sname,
			    (int)((caddr_t)m->caller -
				    (caddr_t)dlinfo.dli_saddr));
		else
			dprintf(fd, "%p\n", m->caller);
	}
on_error:
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

int
memchunk_cmp(struct memchunk *a, struct memchunk *b)
{
	return a - b;
}

RB_GENERATE_STATIC(memchunk_tree, memchunk, tree, memchunk_cmp);

/*
 * Adapted from OpenBSD's lib/libc/stdio/open_memstream.c
 * From $OpenBSD: open_memstream.c,v 1.5 2015/02/05 12:59:57 millert Exp $
 */

/*
 * Copyright (c) 2011 Martin Pieuchot <mpi@openbsd.org>
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

struct state {
	char		 *string;	/* actual stream */
	char		**pbuf;		/* point to the stream */
	size_t		 *psize;	/* point to min(pos, len) */
	size_t		  pos;		/* current position */
	size_t		  size;		/* number of allocated char */
	size_t		  len;		/* length of the data */
	void		 *caller;	/* caller of open_memstream */
};

static int
memstream_write(void *v, const char *b, int l)
{
	struct state	*st = v;
	char		*p;
	size_t		 i, end;

	end = (st->pos + l);

	if (end >= st->size) {
		/* 1.6 is (very) close to the golden ratio. */
		size_t	sz = st->size * 8 / 5;

		if (sz < end + 1)
			sz = end + 1;
		p = realloc0(st->string, sz, st->caller);
		if (!p)
			return (-1);
		bzero(p + st->size, sz - st->size);
		*st->pbuf = st->string = p;
		st->size = sz;
	}

	for (i = 0; i < l; i++)
		st->string[st->pos + i] = b[i];
	st->pos += l;

	if (st->pos > st->len) {
		st->len = st->pos;
		st->string[st->len] = '\0';
	}

	*st->psize = st->pos;

	return (i);
}

static off_t
memstream_seek(void *v, off_t off, int whence)
{
	struct state	*st = v;
	size_t		 base = 0;

	switch (whence) {
	case SEEK_SET:
		break;
	case SEEK_CUR:
		base = st->pos;
		break;
	case SEEK_END:
		base = st->len;
		break;
	}

	if ((off > 0 && off > SIZE_MAX - base) || (off < 0 && base < -off)) {
		errno = EOVERFLOW;
		return (-1);
	}

	st->pos = base + off;
	*st->psize = MINIMUM(st->pos, st->len);

	return (st->pos);
}

static int
memstream_close(void *v)
{
	struct state	*st = v;

	free(st);

	return (0);
}

FILE *
mleakdetect_open_memstream(char **pbuf, size_t *psize, void *caller)
{
	struct state	*st;
	FILE		*fp;

	if (pbuf == NULL || psize == NULL) {
		errno = EINVAL;
		return (NULL);
	}

	if ((st = malloc0(sizeof(*st), caller)) == NULL)
		return (NULL);

	st->size = BUFSIZ;
	if ((st->string = calloc0(1, st->size, caller)) == NULL) {
		free(st);
		return (NULL);
	}

	*st->string = '\0';
	st->pos = 0;
	st->len = 0;
	st->pbuf = pbuf;
	st->psize = psize;
	st->caller = caller;

	*pbuf = st->string;
	*psize = st->len;

	if ((fp = funopen(st, NULL, memstream_write, memstream_seek,
	    memstream_close)) == NULL) {
		free(st);
	}

	return (fp);
}
