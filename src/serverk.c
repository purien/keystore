/* serverk.c */
/* Copyright (C) 2021 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 *
 * This software is an implementation of the internet draft
 * https://tools.ietf.org/html//draft-urien-tls-se-00
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



#ifndef WIN32
   #include <sys/types.h>
   #include <sys/socket.h>
   #include <netinet/in.h>
   #include <arpa/inet.h>
   #include <netdb.h>
   #include <pcsclite.h>
   #define DWORD long
   #define HWND int
  
 
#else
  #include <windows.h>
#endif

#ifdef WIN32
// #include <windows.h>
#elif _POSIX_C_SOURCE >= 199309L
// #include <time.h>   // for nanosleep
#else
#include <unistd.h> // for usleep
#endif

extern void sleep_ms(int milliseconds );

THREAD_CC serverk_thread(void *arg);

extern int gPrintf(int id,char *fmt, ...);

int close_session_console=1;
int racs_verbose=0;
int racs_log=1;
int close_session_delay=0;
int session_console_tile=0;
char strace[128]= {"./" };
char mysocket[128]= {"0.0.0.0:8888"};


extern int APDU(int num_reader,char *req, int sreq, char *resp, int*sresp);
extern int TPDU(int num_reader,char *req, int sreq, char *resp, int*sresp, char *sw1, char *fetch, int id);
extern int Get_Reader_Index_Abs(int id);
extern int NBSC    ;
extern int maxslots;
extern int Reader_Nb_On;

extern int   checkseid(char *id, int uid, int *seid);
extern char * getlistseid();
extern int   getlistmyseid(int uid, char * resp, int *len);

extern int cardreset(int num_reader, int opt,int id);
extern int powerup(int numreader,int id);
extern int powerdown(int numreader,int id);
extern int apdu_firewall(char *apdu, int len, int uid, int seid);


extern int GetUserId(char *name);
extern int closeseid(int sid)   ;
extern int indexs[]             ;
extern int setconsole_name(int id, char *name);
extern int startnewconsole(char *name);
extern int closeconsole(int index);
extern HWND gethWnd(int id);

extern int close_session_console;
extern int racs_verbose;
extern int racs_log;
extern int close_session_delay;
extern int session_console_tile;


int stimeout=30000;

extern int tile();
extern char strace[128];


#define MAX_APDU_RESPONSE             4096
#define RACS_RESPONSE_BUFFER_SIZE     8192
#define MAX_SCRIPT_NAME                 64
#define RACS_RESPONSE_BUFFER_MIN_SIZE 1024




int DumpBuf(char *buf, int len)
{ int i;
  
  for (i=0;i<len;i++)
  { gPrintf(0,"%2.2X ", buf[i] & 0xFF );
    if (i%16 == 15) gPrintf(0,"\n");
  }
  
  if (i%16 != 15) gPrintf(0,"\n");

  return(0);

}







int CheckClientHello(char *rx, char *servername, int max);
int IM_open(int aid,int sid,char * pin);
int IM_send(int aid,int sid,char *in,int lenin, char*out, int *lenout);
int Net_Send(int sock, char *buf, int size);

int do_serverk_loop(int sock, int sid)
{
    int  err,len,pt     ;
 	//int  nwritten     ;
    char buf[4096];
    char buftx[4096]     ;
    char ptcol,vhigh,vlow;

	int ic=-1;
    int stimeout2 ;

    struct timeval timeout;
    fd_set a_fd_set   ;

    struct timeb timebuffer1;
    struct timeb timebuffer2;
    long t1=0,t2=0,dtm=0,rmore=0;

	char sn[128];
	int uid=0,seid=0,aid=0,n=0;
	char servername[16];
	
     struct sockaddr_in sin;
     char ip[32];
	 char fname[MAX_SCRIPT_NAME+1];
	 int port=0;
     FILE *f = NULL ;
     
	 time_t now;
     struct tm tm_now;
     char s_now[sizeof "JJ/MM/AAAA HH:MM:SS"];

	 int first=1;
	 int wrecord=1;
	 int lenr=0;
     int rremain=5;

     stimeout2= stimeout;
     servername[0]=0;

	 /* lire l'heure courante */
    now = time (NULL);
    /* la convertir en heure locale */
    tm_now = *localtime (&now);
    strftime (s_now, sizeof s_now, "%d/%m/%Y %H:%M:%S", &tm_now);
    
	 if (racs_log == 1)
     {	 sprintf(fname,"%skeystore_log_%d.txt",strace,sid);
		 f= fopen(fname,"w+");
	 }



	if (racs_verbose == 1)
	{ sprintf(sn,"Session %d ",sid);
	  ic= startnewconsole((char *)&sn[0]);
      if (session_console_tile == 1)
	    tile();
	}


 
	
   timeout.tv_sec  = 1  ; // secondes
   timeout.tv_usec = 0L ;

  
    ftime(&timebuffer1); 
    t1 =  (int)((timebuffer1.time % 3600)*1000) +   (int)timebuffer1.millitm   ;


   ip[0]=0;
   len = (int)sizeof(sin);
   if (getsockname(sock, (struct sockaddr *)&sin, &len) != 0); //perror("Error on getsockname");
   else
   { strcpy(ip, inet_ntoa(sin.sin_addr)); // IP = 0.0.0.0
     port = sin.sin_port;
   }

  
	if (ic >=0)
		gPrintf(ic,"(%s) Client (%s:%d) is connected (sid=%d)...\n",s_now,ip,port,sid);
	else
        gPrintf(0,"(%s) Client (%s:%d)  is connected (sid=%d)...\n",s_now,ip,port,sid);

    
	if (f != NULL)
		fprintf(f,"(%s) Client (%s:%d) is connected (sid=%d)\r\n",s_now,ip,port,sid);


     pt=0;

	 while(1)
	 {
     
	 rmore=1;

	 while(rmore)
	 {
 	 FD_ZERO(&a_fd_set)       ;
     FD_SET(sock,&a_fd_set)   ;
     err = select (1+sock,&a_fd_set,NULL,NULL,&timeout);
	 
	 if ( FD_ISSET(sock, &a_fd_set) ) 
	 rmore=0;
	 

	 else
	 {
     ftime(&timebuffer2);	
     t2 =  (int)((timebuffer2.time % 3600)*1000) +   (int)timebuffer2.millitm   ;
     dtm = (t2-t1); // ms
    
	 if (dtm <0) dtm += 3600000 ; 

     if (ic >=0)
	 { sprintf(sn,"Session %d Users %s time %d",sid,servername,dtm/1000); 
       #ifdef WIN32
	   setconsole_name(ic,sn);
	   #endif
	 }

     if ( (dtm > (long)stimeout2) || (first && (dtm>10)) )
	 {  gPrintf(0,"Timeout (sid=%d)\n",sid);
	    goto goodbye;
	 }
     }
    
	 } // end of rmore

	 if (wrecord)
	 { err = recv(sock,buf+pt,rremain,0);
	   if (err > 0)
	   { pt+= err;
	     rremain-= err;
	     if (pt == 5)
		 {  wrecord=0;
			ptcol= buf[0];
            vhigh= buf[1];
            vlow=  buf[2];
            lenr  =  (buf[3]<<8) & 0xFF00;
            lenr |=   buf[4] & 0xFF;
			rremain= lenr;
	        if (lenr >= ((int)sizeof(buf))-5)
	        goto goodbye ;
		 }
	   }
	 }

	 else
	 { err = recv(sock,buf+pt,rremain,0);
	   if (err >0) 
	   { pt+= err;
	     rremain -= err;
	   }
	 }

    if (err <= 0) 
		goto goodbye ;

	


	// TLS Flight is ready
	if ( (rremain==0) && (wrecord == 0) )
	{ 
      if (first)
	  { memmove(buftx,buf,5+lenr);
		err= CheckClientHello(buftx,servername,(int)sizeof(servername)-1);
	    first=0;
		if (err <=0)
		{ goto goodbye;
		}
	    if (err >0)
		{  	// get userid
			uid = GetUserId(servername);
			if (uid <0) goto goodbye ;
			// get reader id (aid) and Secure Element ID seid 
            aid = checkseid(servername,uid,&seid);
			if (aid < 0) goto goodbye ;

            err = powerup(aid,sid);
			if (err != 0) goto goodbye ;
            err = cardreset(aid,1,sid);
			if (err != 0) goto goodbye ;
            
			// Applet is default, no PIN code for TLS-PSK
			// err= IM_open(aid,sid,"0000");
            // if (err != 0) goto goodbye ;
        }
	  }
		
      pt = 0   ;
	  rremain=5;
      wrecord=1;

	  err=5+lenr;
	  len = (int)sizeof(buftx);
	  err= IM_send(aid,sid,buf,err,buftx,&len);
      if (err < 0) goto goodbye ;
	  if (err == 1)
	  {  gPrintf(0,"%s TLS in use (sid=%d)\n",servername,sid);
	     if (f != NULL)
	     fprintf(f,"%s TLS in use (sid=%d)\n",servername,sid);
	  }
      
	  if (err == 2)
	  {  if (len != 0) Net_Send(sock,buftx,len);
	     gPrintf(0,"%s TLS close (sid=%d)\n",servername,sid);
		 goto  goodbye ;
	  }

      
	  if (len != 0)
	  { err= Net_Send(sock,buftx,len);
        if (err != 0) goto goodbye ;
	  }
	  
	  
 }  

 } // while(1)




goodbye:

	// shutdown all powered seid
    n=closeseid(sid);
  
	now = time (NULL);
    tm_now = *localtime (&now);
    strftime (s_now, sizeof s_now, "%d/%m/%Y %H:%M:%S", &tm_now);

	gPrintf(0,"(%s) End of session (sid=%d), %d secure elements has been powered off\n",s_now,sid,n);

	if (f != NULL)
	{   fprintf(f,"(%s) End of session (sid=%d), %d secure elements has been powered off\r\n",s_now,sid,n);
		fclose(f);
		f=NULL;
	}

	if ( (ic >=0) && (close_session_console == 1) )
	{	if (close_session_delay > 0) sleep_ms(close_session_delay); 
	    closeconsole(ic);
	}
	
       
   return 0;
}

static int nbsession=0,  y=0;
static int addx(int *x,int n)
 { 
   MUTEX_LOCK(Pmutex[M_SYSTEM]);
   *x = *x + n;
   if (n>=0) y++;
   MUTEX_UNLOCK(Pmutex[M_SYSTEM]);
   return y;
 }


THREAD_CC serverk_thread(void *arg)
{   //int err;
    //PARAMS *params;
    int sock= *((int *)arg);
	int sid;


#ifndef WIN32
    pthread_detach(pthread_self(  ));
#endif

    sid=addx(&nbsession,1);

	gPrintf(0,"Keystore session #%d (sid) opened (total #sessions %d)\n",sid, nbsession);

	do_serverk_loop(sock,sid);
    shutdown(sock,2);
    #ifdef WIN32
    closesocket(sock);
    #endif
	
    
	addx(&nbsession,-1);
	gPrintf(0,"Keystore session #%d (sid) closed (total #sessions %d)\n", sid, nbsession);


#ifdef WIN32
   ExitThread(0);
	   return(0);

	
#endif
}



THREAD_CC daemonk_thread(void *arg)
{ 
  static THREAD_TYPE tid;
  int i;
  unsigned short port= 444;
  char host[200]="0.0.0.0";
  int s;
  struct sockaddr_in addr;
  int sclient;
  int lenaddr;
 
#ifndef WIN32
pthread_detach(pthread_self(  ));
#endif
    
    nbsession=0;
	y=0;

    for (i=0;i<(int)strlen(mysocket);i++)
	{	if (mysocket[i]==(char)':')
	    { sscanf(&mysocket[i+1],"%u",&port);
	      mysocket[i]= 0 ;
		  strcpy(host,mysocket);
		  mysocket[i]= (char)':'; 
	      break;
	    }
	}
    
	//port= 444;


    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr (host); //htonl(INADDR_ANY);

    s = (int) socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) 	{ 
	perror("Unable to create socket");
	exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	perror("Unable to bind");
	exit(EXIT_FAILURE);
    }

    if (listen(s, 10) < 0) {
	perror("Keystore Server Unable to listen");
	exit(EXIT_FAILURE);
    }

    lenaddr = (int)sizeof(addr);

    for (;;)
    {
		gPrintf(0,"Keystore server ready on port %s:%u (total #sessions %d)\n",host,port,nbsession);
        sclient = (int)accept(s,(struct sockaddr*)&addr, &lenaddr);
       
		if (sclient < 0) 
		{   perror("Keystore Server error, unable to accept client");
            exit(EXIT_FAILURE);
		}

  
		THREAD_CREATE(tid, (void *)serverk_thread, &sclient);
    }
   
    
    #ifdef WIN32
	closesocket(s);
    #else
	close(s);
    #endif

	gPrintf(0,"End of Keystore Server Thread\n");

    return 0;



#ifdef WIN32
ExitThread(0);
return(0);
#endif
}

int check_server_name(int len, char *ptr, char *name, int max);

int CheckClientHello(char *rx,char *name, int max)
{  char rec,ptcol, vhigh, vlow  ;
   int lenr, len,cipherlen,extlen;
   char *r,*s,*next;
   int remain;//,found;
   int i,cipher,ii=0;
   int fcipher=-1;
   int extype;//,err,pti;
   //char result[32],
   char v=0;
   char sid[32];
   //char cpk[65];
   int fpsk=0,fdhe=0,fpki=0,ftls13=0,fbinder=0;
   int sidlen;
   int namelen=-1;

  rec  = rx[0];
  vhigh= rx[1];
  vlow=  rx[2];

  lenr  =  (rx[3]<<8) & 0xFF00;
  lenr |=   rx[4] & 0xFF;

  ptcol = rx[5];
  if (rx[6] != 0) return -1;
  len =  (rx[7]<<8) & 0xFF00;
  len |=  rx[8] & 0xFF;
  
  if (len != (lenr-4)) 
	  return -1;
  
  remain=len;

  vhigh= rx[9] ;
  vlow=  rx[10];

 if ( (vhigh != 3) || (vlow != 3) )
	  return -1;
  
  r = &rx[11]; // random 32 bytes

  remain -= 34;
  
  sidlen= 0xFF & rx[43];
  if (sidlen >32) return -1;
  s= &rx[44];
  memmove(sid,&rx[44],sidlen);
  
  remain -= (1+sidlen);

  if (remain <=0) 
	  return -1;

  next= s+sidlen;
  ii= 44+ sidlen;

  remain-=2 ;
  cipherlen  =  (next[0]<<8) & 0xFF00;
  cipherlen |=   next[1] & 0xFF;
  next+=2;
  ii+=2;

  remain -= cipherlen;
  if (remain <=0) 
	  return -1;


  if ( (cipherlen &0x1) == 0x1)
	  return -1;

  for (i=0;i<cipherlen;i+=2)
  {  cipher  =  (next[i]<<8) & 0xFF00;
     cipher |=   next[i+1] & 0xFF;
	 // if (cipher == (int)MY_CIPHER)
	 fcipher=1;
  }

  if (fcipher != 1)
	  return -1;

  next += cipherlen;
  ii+= cipherlen;
  

  remain -=1;
  if (remain <=0) 
	  return -1;
  len = 0xFF & next[0] ;
  
  remain -= len  ;
  if (remain <=0) return -1;


  /*
  found=0;
  for (i=0;i<len;i++)
  { if (next[i+1] == MY_COMPRESS)
	found=1;
  }

  if (!found)  return -1;
  */
  
  next+=(1+len);
  ii+= (1+ len);

  remain -=2;
  if (remain <=0) 
	  return -1;

  extlen  =  (next[0]<<8) & 0xFF00;
  extlen |=   next[1] & 0xFF;
  next+=2;
  ii+=2;

  if (remain != extlen)
	  return -1;

  while (remain != 0)
  {
  remain-=4;
  if (remain <0) 
	  return -1;

  extype  =  (next[0]<<8) & 0xFF00;
  extype |=   next[1] & 0xFF;
  extlen  =  (next[2]<<8) & 0xFF00;
  extlen |=   next[3] & 0xFF;
  remain-=extlen ;
  next+= 4;
  ii+=4;
  
  if (remain < 0) 
	  return -1;

  switch (extype) 
  {

  case 0: // server name
  namelen = check_server_name(extlen,next,name,max);
  
  break;
  
  case 45: // psk_key_exchange_modes
  //err= check_key_exchange(extlen,next);
  //if (err != 0) return -1;
  
  break;

  case 13: // signature_algorithms
  //err= check_signature_algorithms(extlen,next);
  //if (err == 0) fpki= 1;

  break;


  case 41:
  
  //err= check_pre_share_key(extlen,next,&pti);
  //if (err < 0) return -1;
  //fpsk=1;
  
  break;

  case 11:
  // err= check_ec_point_formats(extlen,next);
  // if (err < 0) return -1;
  break;


  case 51:
  //err= check_key_share_extension(extlen,next,&pti);
  //if (err < 0)  return -1;
  //if (err != 65) return -1;
  
  break;

  case 43:
  // err= check_supported_versions(extlen,next);
  // if (err < 0) return -1;
  // ftls13=1;
  break;
 

  case 10:
  //err= check_supported_groups(extlen,next);
  //if (err < 0) return -1;
  break;

  default:
  break;
  }

  next += extlen;
  ii+= extlen;

  }


  return namelen;
}



int check_server_name(int len, char *ptr, char *name, int max)
{ int lenh;
  int lenid;
  int pt;
  int b=0;
  int remain,ni=0,nb=0;

  lenh  =  (ptr[b]<<8) & 0xFF00;
  lenh |=  (ptr[b+1]   & 0xFF );

  pt= 2+lenh;
 
  if (pt != len)
	   return -1;

  remain = lenh;
  b = b+2;
  
  
   remain -=3;
   if (remain <= 0) return -1;
   b++;

   lenid  =  (ptr[b]<<8) & 0xFF00;
   lenid |=  (ptr[b+1]   & 0xFF);

   if (lenid > max)
	   return -1;
   
   remain -= lenid ; 
   
   if (remain < 0) 
	   return -1;

   b+=2;

   memmove(name,ptr+b,lenid);
   name[lenid]=0;
   return lenid  ;
}

static int isDigit(char c)
{ if (((int)c >= (int)'0') && ((int)c<= (int)'9')) return(1);
  if (((int)c >= (int)'A') && ((int)c<= (int)'F')) return(1);
  if (((int)c >= (int)'a') && ((int)c<= (int)'f')) return(1);
  return(0);
}

static int Ascii2bin(char *data_in,char *data_out)
{  	int deb=-1,fin=-1,i,j=0,nc,iCt=0,v,len;
    char c;	
    
	len =(int)strlen(data_in);

	for(i=0;i<len;i++)
	{ if      ( (deb == -1) && (isDigit(data_in[i])) )             {iCt=1;deb=i;}
      else if ( (deb != -1) && (iCt==1) && (isDigit(data_in[i])) ) {iCt=2;fin=i;}

      if (iCt == 2)
	  { c= data_in[fin+1];
	    data_in[deb+1]= data_in[fin];
		data_in[deb+2]= 0;
	    nc = sscanf(&data_in[deb],"%x",&v);
		data_in[fin+1]=c;

		v &= 0xFF;
		data_out[j++]= v ;
		deb=fin=-1;iCt=0;
	   }
    }

return(j);
}




int TxAPDU(int aid, int sid, char *apdu)
{ char buf[900],out[260];
  char Response[260]    ;
  DWORD len,Rsize=260  ;
  int stat;
  int asize=260;

  strcpy(buf,apdu);
  len=  Ascii2bin(buf,out);

  stat= TPDU(aid,out,len,Response,&Rsize,0,0,sid);
  
  if (stat != SCARD_S_SUCCESS)
  return -1 ;
  
  if( (Rsize >=2) && (Response[Rsize-2] == (char)0x90) && (Response[Rsize-1]== (char)0x00) )
	  return 0;
  
  return -1;
}

int IM_open(int aid,int sid,char * pin)
{ int err;
  char verify[128];
    
  err=TxAPDU(aid,sid,"00A4040006010203040500");
  if (err<0) return err;

  sprintf(verify,"0020 0000 %02X %02X %02X %02X %02X", 0xFF & strlen(pin),0xFF&pin[0],0xFF&pin[1],0xFF&pin[2],0xFF&pin[3]);
  err=TxAPDU(aid,sid,verify);
  if (err<0) 
	  return err;

  return (0);
}


int IM_send(int aid,int sid,char *in,int lenin, char*out, int *lenout)
{ char apdu[260];
  char P1=0;
  char response[260];
  int remain, rsize, err, len,cfirst=1,clast=0,ptr=0,ptri=0;
  char sw1= 0x61;
  char fetch[]= {0,0xC0,0,0};

  remain = lenin;
  *lenout=0;
  
  while(1)
  { 
	if (remain <=0)  return -1;

	apdu[0]= 0x00;
    apdu[1]= 0xD8;
    apdu[2]= P1;
    apdu[3]= 0x00;
    
	if (cfirst) { apdu[3]=1; cfirst=0;}//0xFF & len;
	if  (remain <=240){len=remain; clast=1; apdu[3] |= 2; remain=0;}
	else { len = 240; remain -= len;}
    
	apdu[4]= 0xFF & len ;

    memmove(&apdu[5],in+ptr,len);

    // err= txAPDU(apdu,5+len,response,&rsize);
	rsize = (int)sizeof(response);
	err= TPDU(aid,apdu,5+len,response,&rsize,&sw1,fetch,sid);
	ptr+= len;

    if (err<0)     return -1;
	if (rsize <2)  return -1;

	if ( (rsize > 2) && !clast ) return -1;
    
	if (rsize > 2 )
	{ memmove(out+ptri,response,rsize-2);
	  ptri+= (rsize-2);
	  *lenout=ptri;
	}
	
    if ( (response[rsize-2]==(char)0x90) && (response[rsize-1]==(char)0x00) )
	{ if (!clast) continue ;
	  else        return 0 ;
	}

	else if (response[rsize-2]==(char)0x9F) 
	{   if (!clast) return -1;
		len = 0xFF & response[rsize-1];
		break;
	}
    else  if (response[rsize-2]==(char)0x90) 
	{ if (!clast)  return -1;
	  else         return 0xFF & response[rsize-1] ;
	}

	else
	return -1;
  }

  while(1)
  {
    apdu[0]= 0x00;
    apdu[1]= 0xC0;
    apdu[2]= 0x00;
    apdu[3]= 0x00 ;
    apdu[4]= 0xFF & len ;

    // err= txAPDU(apdu,5,response,&rsize);
    rsize = (int)sizeof(response);
    err= TPDU(aid,apdu,5,response,&rsize,&sw1,fetch,sid);

    if (err<0)     return -1;
	if (rsize <2)  return -1;
	
	if (rsize >2)
	{  memmove(out+ptri,response,rsize-2);
	   ptri+= (rsize-2);
      *lenout=ptri;
	}

    if ( (response[rsize-2]==(char)0x90) && (response[rsize-1]==(char)0x00) )
	{ return 0 ;
	}

	else if (response[rsize-2]==(char)0x9F) 
	{   len = 0xFF & response[rsize-1];
	}

	else  if (response[rsize-2]==(char)0x90) 
	return 0xFF & response[rsize-1] ;

	else
	return -1;

  }

  return 0;
}

int Net_Send(int sock, char *buf, int size)
{ int err,offset=0,more=1;
 
  
  while (more)
  { err = send(sock,((char *)buf)+offset,size-offset,0) ;
  if (err <= 0) return -1;
	offset+= err ;
	if (offset == size) more=0;
  }
  
  return 0 ;
}




