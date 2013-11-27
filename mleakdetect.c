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
#include <string.h>
#include <unistd.h>

struct memchunk {
	void			*caller;
	size_t			 size;
	int			 count;
	TAILQ_ENTRY(memchunk)	 next;
	u_char data[0];
};
TAILQ_HEAD(memchunk_head, memchunk);

struct memchunk_head	   mleakdetect_memchunk;
struct memchunk_head	   mleakdetect_stat;
static void		*(*mleakdetect_malloc)(size_t) = NULL;
static void		 (*mleakdetect_free)(void *) = NULL;
static int		   mleakdetect_initialized = 0; 
static int		   mleakdetect_malloc_count = 0; 
static int		   mleakdetect_free_count = 0; 
static int		   mleakdetect_unknown_free_count = 0; 
static int		   mleakdetect_stopped = 0;

static void	*malloc0 (size_t, void *);
static void	 mleakdetect_initialize (void);
static void	 mleakdetect_atexit (void);
void		 mleakdetect_dump (int);

static void
mleakdetect_initialize(void)
{
	void	*libc_h;

	if ((libc_h = dlopen("libc.so", RTLD_NOW)) == NULL)
		return;

	TAILQ_INIT(&mleakdetect_memchunk);
	TAILQ_INIT(&mleakdetect_stat);

	mleakdetect_malloc  = dlsym(libc_h, "malloc");
	mleakdetect_free    = dlsym(libc_h, "free");

	mleakdetect_initialized = 1;

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

	mleakdetect_malloc_count++;
	m->size = size;
	m->caller = caller;
	TAILQ_INSERT_TAIL(&mleakdetect_memchunk, m, next);

	return (m->data);
}

void *
realloc(void *ptr, size_t size)
{
	void *r;
	struct memchunk *m;

	if (mleakdetect_initialized == 0)
		mleakdetect_initialize();

	if (ptr == NULL)
		return malloc0(size, __builtin_return_address(0));

	TAILQ_FOREACH(m, &mleakdetect_memchunk, next) {
		if (m->data == ptr)
			break;
	}
	r = malloc0(size, __builtin_return_address(0));
	if (r == NULL)
		return (r);
	memcpy(r, m->data, MIN(m->size, size));
	if (m != NULL)
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

	mleakdetect_malloc_count++;
	m->size = (nmemb + cnt) * size;
	m->caller = __builtin_return_address(0);
	TAILQ_INSERT_TAIL(&mleakdetect_memchunk, m, next);

	return (m->data);
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
	int	 lstr;

	lstr = MIN(strlen(str), maxlen) + 1;
	p = malloc0(lstr, __builtin_return_address(0));
	strlcpy(p, str, lstr);

	return (p);
}

void
free(void *mem)
{
	struct memchunk	*m, *mt;

	if (mleakdetect_stopped) {
		mleakdetect_free(mem);
		return;
	}
	if (mleakdetect_initialized == 0)
		mleakdetect_initialize();

	TAILQ_FOREACH_SAFE(m, &mleakdetect_memchunk, next, mt) {
		if (m->data == mem) {
			TAILQ_REMOVE(&mleakdetect_memchunk, m, next);
			mleakdetect_free_count++;
			mleakdetect_free(m);
			return;
		}
	}
	mleakdetect_unknown_free_count++;
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

	/* buffle sort by size */
	l = NULL;
	m = TAILQ_FIRST(&mleakdetect_stat);
	n = TAILQ_NEXT(m, next);
	do {
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
	} while (n != l && m != l);

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
