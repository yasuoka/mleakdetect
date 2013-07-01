CC?=		gcc
CPPFLAGS?=	-Wall
RM?=		rm -f

mleakdetect.so: mleakdetect.c
	${CC} ${CPPFLAGS} -shared -o $@ mleakdetect.c

clean:
	${RM} mleakdetect.so
