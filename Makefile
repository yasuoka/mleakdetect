CC?=		gcc
CPPFLAGS+=	-Wall
CFLAGS=		-fPIC -g
RM?=		rm -f

mleakdetect.so: mleakdetect.c
	${CC} ${CFLAGS} ${CPPFLAGS} -shared -o $@ mleakdetect.c

clean:
	${RM} mleakdetect.so
