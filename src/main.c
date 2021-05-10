/* main.c */
/* Copyright (C) 2021 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 *
 * This software is an implementation of the internet draft
 * https://tools.ietf.org/html/draft-urien-tls-se-00
 * "Secure Element for TLS Version 1.3" by Pascal Urien.
 * The implementation was written so as to conform with this draft.
 * 
 * This software is free for non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution.
 * 
 * Copyright remains Pascal Urien's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Pascal Urien should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes KEYSTORE-Server software written by
 *     Pascal Urien (pascal.urien@gmail.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY PASCAL URIEN ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */



#ifdef WIN32
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE
#endif

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/timeb.h>

#include "common.h"
#include "mutuex.h"
#include "readers.h"

#ifdef WIN32
#include <windows.h>
#elif _POSIX_C_SOURCE >= 199309L
// #include <time.h>   // for nanosleep
#else
#include <unistd.h> // for usleep
#endif

void sleep_ms(int milliseconds );
int gPrintf(int id,char *fmt, ...);

THREAD_CC mythread(void *arg);
static char mystr[64][64000] ;


extern int  buildlistseid();
extern int  serverdefault();
extern char *Get_Reader_Name(int index_abs);
extern int  Get_Nb_Reader_On();
extern int  Get_Reader_Index_Abs(index_on);
extern int  start(int num_reader);
extern int  StartAll();
extern int  CloseAll();
extern int  indexs[];
extern int  ReadAllTables(char *base);
//extern THREAD_CC daemon_thread(void *arg);
extern THREAD_CC daemonk_thread(void *arg);

//THREAD_TYPE tids;
THREAD_TYPE tids2;


void testtime(int delay)
{  struct timeb t1,t2;
   long dtm,T1,T2;
   ftime(&t1);
   sleep_ms(2000);
   ftime(&t2);

   T1 =  (int)(0xFFFFFFFF & (t1.time % 3600)*1000 +   t1.millitm)   ;
   T2 =  (int)(0xFFFFFFFF & (t2.time % 3600)*1000 +   t2.millitm)  ;
   dtm = (T2-T1);
   if (dtm <0) dtm += 3600000 ;
   printf("%ld\n",dtm);

}

static int aindex[2] ;

void testthread()
{ THREAD_TYPE tid1,tid2;
  aindex[0]=1;
  THREAD_CREATE(tid1, mythread, (void*)&aindex[0]);
  aindex[1]=2;
  THREAD_CREATE(tid2, mythread, (void*)&aindex[1]);
}

main(int argc, char **argv)
{  int i;
   #ifdef WIN32
   WSADATA wsaData ;
   #endif
 
   #ifdef WIN32
   WSAStartup(MAKEWORD(1,1),&wsaData) ; 
   #endif
       
   if (argc == 1)
   ReadAllTables(NULL);
   else
   ReadAllTables(argv[1]);

   MutexSetup(M_SYSTEM+1);
   buildlistseid();
  

  StartAll(); // return the number of OnReader

  for(i=0;i<Get_Nb_Reader_On();i++) indexs[Get_Reader_Index_Abs(i)]= 1+i;

  for(i=0;i<Get_Nb_Reader_On();i++) start(Get_Reader_Index_Abs(i)); // Start OnReaders


 
   THREAD_CREATE(tids2, (void *)daemonk_thread,NULL); 


  
   while(1)
   sleep_ms(1000);

    #ifdef WIN32
	WSACleanup();
    #endif


    Mutex_cleanup(M_SYSTEM+1);

   return 0;
}


THREAD_CC mythread(void *arg)
{  
    int * id = (int *) arg;
    int i;

#ifndef WIN32
    pthread_detach(pthread_self(  ));
#endif


    MUTEX_LOCK(Pmutex[0]);
  
	for(i=0;i<10;i++)
	{ gPrintf(0,"%s %d\n","Hello World ",*id);
	   sleep_ms(25);
	}

    MUTEX_UNLOCK(Pmutex[0]);
 

#ifdef WIN32
 ExitThread(0);
 return(0);

	
#endif
}





int gPrintf(int id,char *fmt, ...)
{ va_list  argptr  ;
  
  int  cnt ;
  
  MUTEX_LOCK(Pmutex[id]);

  va_start(argptr,fmt) ;
  cnt = vsprintf(mystr[id],fmt, argptr ) ;
  va_end( argptr );
 
  printf("%s",mystr[id]);

  MUTEX_UNLOCK(Pmutex[id]);

 return( cnt )   ;
}



void sleep_ms(int milliseconds) // cross-platform sleep function
{
#ifdef WIN32
    Sleep(milliseconds);
#elif _POSIX_C_SOURCE >= 199309L
    struct timespec ts;
    ts.tv_sec = milliseconds / 1000;
    ts.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&ts, NULL);
#else
    usleep(milliseconds * 1000);
#endif
}


