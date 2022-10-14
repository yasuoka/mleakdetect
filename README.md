mleakdetect.so
==============

minimum memory leak checker.  Currently this works on OpenBSD.

Compile
-------

    % make
    cc -fPIC -g -Wall -shared -o mleakdetect.so mleakdetect.c
    %

Usage
-----

To check `cal' command leaks.


    % env LD_PRELOAD=./mleakdetect.so /usr/bin/cal
       November 2013
    Su Mo Tu We Th Fr Sa
		    1  2
     3  4  5  6  7  8  9
    10 11 12 13 14 15 16
    17 18 19 20 21 22 23
    24 25 26 27 28 29 30


    cal (pid=29747) mleakdetect report:
	malloc                 3
	free                   1
	unknown free           0
	unfreed                2 ( 66.67%)
	total leaks        92496

    memory leaks:
	total bytes  count  avg. bytes  calling func(addr)
	      65536      1       65536  __smakebuf+0x6c
	      26960      1       26960  gmtime_r+0x446
    %


mleakdect.so try to output the result to the standard error output
when the target program is exiting.  But if the program crashs or aborts,
it cannot output the result.  Use gdb for such cases.

    % cat 1.c
    #include <stdlib.h>

    int
    main(int argc, char *argv)
    {
	    void *m;

	    m = malloc(1000000);

	    *(int *)0 = 1;	/* cause segmentation fault */

	    exit(0);
    }
    % cc -g 1.c
    % ./a.out
    Segmentation fault (core dumped)
    % gdb a.out
    GNU gdb 6.3
      :
      (snip)
      :
    (gdb) set environment LD_PRELOAD=./mleakdetect.so
    (gdb) run
    Starting program: /home/..(snip)../mleakdetect/a.out

    Program received signal SIGSEGV, Segmentation fault.
    0x00001155e4000d92 in main (argc=1, argv=0x7f7ffffcf118 "") at 1.c:10
    10              *(int *)0 = 1;  /* cause segmentation fault */
    (gdb) call mleakdetect_dump(2)

    a.out (pid=29747) mleakdetect report:
	malloc                 1
	free                   0
	unknown free           0
	unfreed                1 (100.00%)
	total leaks      1000000

    memory leaks:
	total bytes  count  avg. bytes  calling func(addr)
	    1000000      1     1000000  0x1155e4000d89
    $1 = 0
    (gdb)

Normally symbol names of the executable itself are not resolved.
Compile the executable with -Wl,-E if you want to use this with the
symbol names.

    % cc -g -Wl,-E 1.c
    % gdb a.out
    GNU gdb 6.3
      :
      (snip)
      :
    (gdb) set environment LD_PRELOAD=./mleakdetect.so
    (gdb) run
    Starting program: /disk1/home/yasuoka/mleakdetect/a.out

    Program received signal SIGSEGV, Segmentation fault.
    0x0000000000400a52 in main (argc=1, argv=0x7f7ffffced68 "") at 1.c:10
    10                  *(int *)0 = 1;      /* cause segmentation fault */
    (gdb) call mleakdetect_dump(2)

    a.out (pid=17855) mleakdetect report:
	malloc                 1
	free                   0
	unknown free           0
	unfreed                1 (100.00%)
	total leaks      1000000

    memory leaks:
	total bytes  count  avg. bytes  calling func(addr)
	    1000000      1     1000000  main+0x19
    (gdb) 
