mleakdetect.so
==============

minimum memory leak checker

Compile
-------

    % make
    cc  -shared -o mleakdetect.so mleakdetect.c
    %

Usage
-----

To check `make' command leaks.

    % env LD_PRELOAD=./mleakdetect.so make
    mleakdetect report:
        malloc               579
        free                  86
        unknown free         105
        unfreed              493 ( 85.15%)
        total leaks        88277
    
    memory leaks:
        total bytes  count  avg. bytes  calling func(addr)
              36209      9        4023  Dir_Destroy+0x802e
              34188    477          71  Dir_Destroy+0x8086
              16384      1       16384  __smakebuf+0x6c
               1024      2         512  Dir_Destroy+0x7fe6
                360      1         360  setenv+0x13b
                112      3          37  setenv+0x199
    `mleakdetect.so' is up to date.
    %

mleakdect.so try to output the result to the standard error output
when the target program is exiting.  But if the program crashs or aborts,
it cannot outoput the result.  Use gdb for such case.

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
    0x00001155e4000d92 in main (argc=1, argv=0x7f7ffffcf118 "\020ÿ\177\177")
	at 1.c:10
    10              *(int *)0 = 1;  /* cause segmentation fault */
    (gdb) call mleakdetect_dump(2)

    mleakdetect report:
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
