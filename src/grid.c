/* grid.c */
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/timeb.h>
#include <time.h>
#include <malloc.h>

#ifndef WIN32
   #include <sys/types.h>
   #include <sys/socket.h>
   #include <netinet/in.h>
   #include <arpa/inet.h>
   #include <netdb.h>
   #define DWORD long
#else
  #include <winsock.h>
#endif


extern int  indexs[]                       ;
extern int  Get_Reader_Index_Abs(int id)   ;
extern int  gPrintf(int id,char *fmt, ... );

int Ascii2bin(char *data_in,char *data_out);

char gridserver[128]="gridserver.com";
unsigned short gridport=51503;
int  maxslots=1   ;
int  startslot=24 ;
int  NBSC=0       ;
char board[32]="7";

extern long DTM       ;
extern char mysocket[];

#define MAX_MSG 2048

int verbose2=1     ;
char cacheHost[256];
int  cacheIP=0     ;


int SetConnectAddress(struct sockaddr_in *sin,unsigned short port,char *host)
{ 
 struct hostent *phe ;
	 
 sin->sin_family      = AF_INET    ;
 sin->sin_port        = htons(port);
 	 
 if ( (cacheIP !=0) && (strcmp(host,cacheHost)==0) )
 {  sin->sin_addr.s_addr = cacheIP;
 }
 
 else
 {
 sin->sin_addr.s_addr = inet_addr (host);
 cacheIP=0;
 cacheHost[0]=0;

 if (sin->sin_addr.s_addr == INADDR_NONE)
 {
	  phe = gethostbyname (host);
	  if (phe == NULL) return(0);
      
      else     
      memcpy(&(sin->sin_addr),phe->h_addr,4);
	  
	  if (sin->sin_addr.s_addr == INADDR_NONE)
	  return(0); 
	  
 }

 cacheIP= sin->sin_addr.s_addr ;
 strcpy(cacheHost,host);

 }
return(1);
 
}



int InitializeGrid()
{ 
  return(NBSC)  ;
}

int ConnectGridSc(int nbCard, int * sc)
{
	struct sockaddr_in sin,csin   ; 
	int  err, namelen;
	int client;  
	
	int idp;
    idp= indexs[Get_Reader_Index_Abs(nbCard-1-startslot)];


    // nbCard= 1...n

    client = (int) socket (AF_INET,SOCK_STREAM,0); 
	*sc= client;

    csin.sin_family = AF_INET   ;  
    csin.sin_port   = 0 ;  
    csin.sin_addr.s_addr =  INADDR_ANY;  
 
    err = bind (client,(struct sockaddr *) &csin, sizeof (csin));	
	if (err != 0)
	{ gPrintf(idp,"Socket Bind Error !!!\n");
	  return 0;
	}

    namelen = sizeof(csin);
    err = getsockname(client, (struct sockaddr *) &csin, &namelen);
 
    sin.sin_family = AF_INET   ;  
    sin.sin_port = htons(gridport) ;  
    sin.sin_addr.s_addr =  inet_addr("93.218.83.100") ;


   if (!SetConnectAddress(&sin,(unsigned short)gridport,gridserver))
   {
	   gPrintf(idp,"DNS error for grid server...\n");
	   return -1;
   }

    err= connect(client,(struct sockaddr *) &sin,sizeof(struct sockaddr) );

	if (err != 0)
	{ gPrintf(idp,"Connection to Grid Server Failed !!!\n");
	  return 0;
	}
    
    return 1;

}
  
int DeconnectGridSc(int nbCard, int * sc)
{ int client;	

  client = *sc ;
 
  shutdown(client,2) ;
  #ifndef WIN32
  close(client);
  #else
  closesocket(client);
  #endif

  

  return (0);

}
  


int SendGridSc(int *sc, char* APDU, DWORD APDUlen, char* Response, DWORD* Rlen, int nbCard, int port)
{

	return(-1);
}

//======================
// Usefull procedures
//======================
int isDigit(char c)
{ if (((int)c >= (int)'0') && ((int)c<= (int)'9')) return(1);
  if (((int)c >= (int)'A') && ((int)c<= (int)'F')) return(1);
  if (((int)c >= (int)'a') && ((int)c<= (int)'f')) return(1);
  return(0);
}

int Ascii2bin(char *Data_In,char *data_out)
{  	int deb=-1,fin=-1,i,j=0,nc,iCt=0,v,len;
    char c;	
	char data_in[MAX_MSG] ;
    
	len =(int)strlen(Data_In);

	strcpy(data_in,Data_In);

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


