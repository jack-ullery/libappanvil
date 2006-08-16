INCLUDE=/usr/lib/java/include
TOP=../..
CLASSPATH=${TOP}/build
CFLAGS=-g -O2 -Wall -Wstrict-prototypes -pipe  -fpic -D_REENTRANT
INCLUDES=-I$(INCLUDE)  -I$(INCLUDE)/linux
CLASSFILE=${CLASSPATH}/com/novell/apparmor/JNIChangeHat.class

all:
	make jnichangehat

jnichangehat:  libJNIChangehat.so

clean:
	rm -f ${TOP}/dist/*.so  JNIChangeHat.java com_novell_apparmor_JNIChangeHat.h


JNIChangeHat.java com_novell_apparmor_JNIChangeHat.h:  ${CLASSFILE}
	javah -jni -classpath ${CLASSPATH} com.novell.apparmor.JNIChangeHat 

libJNIChangehat.so:    JNIChangeHat.c  JNIChangeHat.java com_novell_apparmor_JNIChangeHat.h
	gcc ${INCLUDES} ${CFLAGS} -shared -o ${TOP}/dist/libJNIChangeHat.so  JNIChangeHat.c -lapparmor
