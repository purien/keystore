/* pcscemulator.c */
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

#ifdef WIN32
 #include <windows.h>
#endif

#include <time.h>
#include <sys/timeb.h>
#include <memory.h>

#include <winscard.h>

#include "pcscemulator.h"
#include "grid.h"

#define MIN(a,b) (((a)<(b))?(a):(b))

static DWORD ptcol = SCARD_PROTOCOL_T0;
static int sc[2048];


// WINSCARDDATA const SCARD_IO_REQUEST
//    g_rgSCardT0Pci,
//    g_rgSCardT1Pci,
//    g_rgSCardRawPci;

// #define SCARD_PCI_T0  (&g_rgSCardT0Pci)
// #define SCARD_PCI_T1  (&g_rgSCardT1Pci)
// #define SCARD_PCI_RAW (&g_rgSCardRawPci)

WINSCARDAPI LONG WINAPI
SCardEstablishContext2(
    IN  DWORD dwScope,
    IN  LPCVOID pvReserved1,
    IN  LPCVOID pvReserved2,
    OUT LPSCARDCONTEXT phContext);

WINSCARDAPI LONG WINAPI
SCardReleaseContext2(
    IN      SCARDCONTEXT hContext);
    
WINSCARDAPI LONG WINAPI
SCardListReadersA2(
    IN      SCARDCONTEXT hContext,
    IN      LPCSTR mszGroups,
    OUT     LPSTR mszReaders,
    IN OUT  LPDWORD pcchReaders);

WINSCARDAPI LONG WINAPI
SCardTransmit2(
    IN SCARDHANDLE hCard,
    IN LPCSCARD_IO_REQUEST pioSendPci,
    IN LPCBYTE pbSendBuffer,
    IN DWORD cbSendLength,
    IN OUT LPSCARD_IO_REQUEST pioRecvPci,
    OUT LPBYTE pbRecvBuffer,
    IN OUT LPDWORD pcbRecvLength);


WINSCARDAPI LONG WINAPI
SCardConnectA2(
    IN      SCARDCONTEXT hContext,
    IN      LPCSTR szReader,
    IN      DWORD dwShareMode,
    IN      DWORD dwPreferredProtocols,
    OUT     LPSCARDHANDLE phCard,
    OUT     LPDWORD pdwActiveProtocol);


WINSCARDAPI LONG WINAPI
SCardReconnect2(
    IN      SCARDHANDLE hCard,
    IN      DWORD dwShareMode,
    IN      DWORD dwPreferredProtocols,
    IN      DWORD dwInitialization,
    OUT     LPDWORD pdwActiveProtocol);


WINSCARDAPI LONG WINAPI
SCardDisconnect2(
    IN      SCARDHANDLE hCard,
    IN      DWORD dwDisposition);

WINSCARDAPI LONG WINAPI
SCardState2(
    IN SCARDHANDLE hCard,
    OUT LPDWORD pdwState,
    OUT LPDWORD pdwProtocol,
    OUT LPBYTE pbAtr,
    OUT LPDWORD pcbAtrLen);

#ifdef UNICODE_NAME

WINSCARDAPI LONG WINAPI
SCardListReadersW2(
    IN      SCARDCONTEXT hContext,
    IN      LPCWSTR mszGroups,
    OUT     LPWSTR mszReaders,
    IN OUT  LPDWORD pcchReaders);


WINSCARDAPI LONG WINAPI
SCardConnectW2(
    IN      SCARDCONTEXT hContext,
    IN      LPCWSTR szReader,
    IN      DWORD dwShareMode,
    IN      DWORD dwPreferredProtocols,
    OUT     LPSCARDHANDLE phCard,
    OUT     LPDWORD pdwActiveProtocol);

#endif

//====================================

int isGridSc(LPSCARDHANDLE phCard)
{

	if ((int)*phCard <= 0)
		return -1;

	if ( ((int)*phCard >= (int)1024) && ((int)*phCard <= (int)2048) )
		return 		
		  (int)((int)*phCard - (int)1024 + (int)1 );

	return -1;

}


int GetGridSc(char* szReader)
{  int nb=-1; 
   char c;


	if ((int)strlen(szReader) < 5)
		return -1;

    c= szReader[4];
	szReader[4]=(char)0;

    if (strcmp(szReader,"grid") != 0)
	{szReader[4]=c;
	 return -1;
	}
    szReader[4]=c;
	sscanf(&szReader[4],"%d",&nb);
    
	return nb;

}

#ifdef UNICODE_NAME

int GetGridScW(wchar_t * szReader)
{  int nb=-1; 
   wchar_t c;


	if ((int)wcslen(szReader) < 5)
		return -1;

    c= szReader[4];
	szReader[4]=(char)0;

    if (wcscmp(szReader,L"grid") != 0)
	{szReader[4]=c;
	 return -1;
	}
    szReader[4]=c;
	swscanf(&szReader[4],L"%d",&nb);
    
	return nb;

}


#endif


WINSCARDAPI LONG WINAPI
SCardEstablishContext2(
    IN  DWORD dwScope,
    IN  LPCVOID pvReserved1,
    IN  LPCVOID pvReserved2,
    OUT LPSCARDCONTEXT phContext)
{ 
	LONG stat= SCARD_S_SUCCESS;
	
	stat = SCardEstablishContext(dwScope,pvReserved1,pvReserved2,phContext);

return stat;
}


WINSCARDAPI LONG WINAPI
SCardReleaseContext2(
IN      SCARDCONTEXT hContext)
{
  LONG stat;

  stat= SCardReleaseContext(hContext);

  return stat;
}



extern int maxslots;

WINSCARDAPI LONG WINAPI
SCardListReadersA2(
    IN      SCARDCONTEXT hContext,
    IN      LPCSTR mszGroups,
    OUT     LPSTR mszReaders,
    IN OUT  LPDWORD pcchReaders	)
{ 
int i;
LONG stat;
DWORD ptr=0;
#ifndef WIN32
LPTSTR list;
DWORD wlist;
SCARDCONTEXT hContext2;
#endif
//int NBSC=0;

 InitializeGrid();
 maxslots = MIN(maxslots,NBSC);


for (i=1;i<=NBSC;i++)
{
sprintf(&mszReaders[ptr],"grid%03d",i);
ptr += 8;
}

*pcchReaders = *pcchReaders - ptr;

#ifndef WIN32


 stat = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext2);
 if (stat != SCARD_S_SUCCESS)
 {
     return (SCARD_S_SUCCESS);
 }

#ifdef SCARD_AUTOALLOCATE
 wlist = SCARD_AUTOALLOCATE;

 stat = SCardListReaders(hContext2, NULL, (LPTSTR)&list, &wlist);
 if (stat != SCARD_S_SUCCESS)
 {
     return (SCARD_S_SUCCESS);
 }
#else
 stat = SCardListReaders(hContext2, NULL, NULL, &wlist);
  if (stat != SCARD_S_SUCCESS)
 {
     return (SCARD_S_SUCCESS);
 }

 mszReaders = calloc(dwReaders, sizeof(char));
 stat = SCardListReaders(hContext2, NULL, (LPTSTR)&list, &wlist);
  if (stat != SCARD_S_SUCCESS)
 {
     return (SCARD_S_SUCCESS);
     
 }
#endif

memcpy(mszReaders+ptr,list,wlist)  ;
*pcchReaders = *pcchReaders - wlist;

#ifdef SCARD_AUTOALLOCATE
 stat = SCardFreeMemory(hContext2, list);
 #else
 free(list);
#endif

stat = SCardReleaseContext(hContext2);

#else
stat = SCardListReaders(hContext,mszGroups,mszReaders+ptr,pcchReaders);
#endif

return stat;

}


#ifdef UNICODE_NAME


WINSCARDAPI LONG WINAPI
SCardListReadersW2(
    IN      SCARDCONTEXT hContext,
    IN      LPCWSTR mszGroups,
    OUT     LPWSTR mszReaders,
    IN OUT  LPDWORD pcchReaders	)
{ 
int i;
LONG stat;
DWORD ptr=0;

InitializeGrid();
//NBSC=1;

for (i=1;i<=NBSC;i++)
{
wsprintf(&mszReaders[ptr],L"grid%03d",i);
ptr += 16;
}

*pcchReaders = *pcchReaders - ptr;


stat = SCardListReadersW(hContext,mszGroups,mszReaders+ptr,pcchReaders);


return stat;

}

#endif


long DTM=0;

WINSCARDAPI LONG WINAPI
SCardTransmit2(
    IN SCARDHANDLE hCard,
    IN LPCSCARD_IO_REQUEST pioSendPci,
    IN LPCBYTE pbSendBuffer,
    IN DWORD cbSendLength,
    IN OUT LPSCARD_IO_REQUEST pioRecvPci,
    OUT LPBYTE pbRecvBuffer,
    IN OUT LPDWORD pcbRecvLength)

{  LONG stat= SCARD_S_SUCCESS;
   int nb,err; 
   struct timeb timebuffer1;
   struct timeb timebuffer2;
   long t1=0,t2=0,dtm=0;
   //BYTE more[] = {(BYTE)0x00, (BYTE)0xC0, (BYTE)0x00, (BYTE)0x00,(BYTE)0x00};
   int todo=1,lenr=0 ;
   DWORD len;

   len = *pcbRecvLength;

   while(todo)
   {  
	   dtm=0;
	   todo=0;

   // Retourne le #du slot 0 (index) dans la grille => 1 dans la grille implementa
   nb = isGridSc(&hCard);

   if (nb <= 0)
   {
    ftime(&timebuffer1);
    stat = SCardTransmit(hCard,pioSendPci,pbSendBuffer,cbSendLength,pioRecvPci, pbRecvBuffer,pcbRecvLength);	
    ftime(&timebuffer2);	
   
    t1 =  (int)((timebuffer1.time % 3600)*1000) +   (int)timebuffer1.millitm   ;
    t2 =  (int)((timebuffer2.time % 3600)*1000) +   (int)timebuffer2.millitm   ;
    dtm = (t2-t1);
    
	if (dtm <0) 
		dtm += 3600000 ;

	DTM+= dtm;
    //Printf(">> %d ms\n",dtm);

   }

   else
   {   err = SendGridSc(&sc[nb-1],(char *)pbSendBuffer,cbSendLength,(char *)pbRecvBuffer,pcbRecvLength,nb,0);
       if (err <0)
		   return -1;
   }

   /*
   if ( (*pcbRecvLength == (DWORD)2) && (*pbRecvBuffer == (BYTE)0x61)  )
   { memmove((void *)pbSendBuffer, (void *)more, 5);
     cbSendLength=5;
	 memmove((void*)(pbSendBuffer+4), (void *)(pbRecvBuffer+1),1);
	 *pcbRecvLength = len;
	 todo=1;
   }
   */

   }
   
   
   return stat;
  

}
// extern int SerialApdu(HANDLE handle,char *req, int rlen, char *resp, int *plen);

//static char more[]= {(char)0xA0,(char)0xC0,(char)0x00,(char)0x00,(char)00};


WINSCARDAPI LONG WINAPI
SCardConnectA2(
    IN      SCARDCONTEXT hContext,
    IN      LPCSTR szReader,
    IN      DWORD dwShareMode,
    IN      DWORD dwPreferredProtocols,
    OUT     LPSCARDHANDLE phCard,
    OUT     LPDWORD pdwActiveProtocol)
{  LONG stat= SCARD_S_SUCCESS;
   int nb=-1,err=0;
   
   nb = GetGridSc((char*)szReader);
   if (nb >0)
   { *phCard = (SCARDHANDLE)(1024+nb-1)   ;
     err= ConnectGridSc(nb,&sc[nb-1] );
 	 if (err<=0) 
		 return -1;
     *pdwActiveProtocol=SCARD_PROTOCOL_T0 ;
   }
   else
	   stat= SCardConnect(hContext,szReader,dwShareMode,dwPreferredProtocols,phCard,pdwActiveProtocol);
 
return(stat);
}

#ifdef UNICODE_NAME

WINSCARDAPI LONG WINAPI
SCardConnectW2(
    IN      SCARDCONTEXT hContext,
    IN      LPCWSTR szReader,
    IN      DWORD dwShareMode,
    IN      DWORD dwPreferredProtocols,
    OUT     LPSCARDHANDLE phCard,
    OUT     LPDWORD pdwActiveProtocol)

{  LONG stat= SCARD_S_SUCCESS;
   int nb=-1,err=0;

   nb = GetGridScW((wchar_t *)szReader);
   if (nb >0)
   { *phCard = (SCARDHANDLE)(1024+nb-1);
     err= ConnectGridSc(nb,&sc[nb-1]);
	 if (err<=0) 
		 return -1;
	 *pdwActiveProtocol=SCARD_PROTOCOL_T0 ;

   }
   else
	   stat= SCardConnectW2(hContext,szReader,dwShareMode,dwPreferredProtocols,phCard,pdwActiveProtocol);
 
return(stat);
}


#endif




WINSCARDAPI LONG WINAPI
SCardReconnect2(
    IN      SCARDHANDLE hCard,
    IN      DWORD dwShareMode,
    IN      DWORD dwPreferredProtocols,
    IN      DWORD dwInitialization,
    OUT     LPDWORD pdwActiveProtocol)
{ LONG stat = SCARD_S_SUCCESS ;
  int nb=-1;

  nb= isGridSc(&hCard);

 if (nb <=0 )
 stat= SCardReconnect(hCard,dwShareMode,dwPreferredProtocols,dwInitialization,pdwActiveProtocol);


return stat ;
}


WINSCARDAPI LONG WINAPI
SCardDisconnect2(
    IN      SCARDHANDLE hCard,
    IN      DWORD dwDisposition)
{ 
LONG stat=SCARD_S_SUCCESS;
int nb;

nb= isGridSc(&hCard);

if ( nb <= 0 )
stat= SCardDisconnect(hCard,dwDisposition);

else
DeconnectGridSc(nb, &sc[nb-1]);

return stat;
}

static char atr[] = {(char)0x3B,(char)0x07,(char)'G',(char)'R',(char)'I',(char)'D',(char)'0', (char)'0',(char)'0',(char)0};


WINSCARDAPI LONG WINAPI
SCardGetAttrib2(
    IN SCARDHANDLE hCard,
    IN DWORD dwAttrId,
    OUT LPBYTE pbAttr,
    IN OUT LPDWORD pcbAttrLen)
{
    LONG stat= SCARD_S_SUCCESS ;
	int nb;

	nb= isGridSc(&hCard);

    if (nb <= 0)
    stat = SCardGetAttrib(hCard,dwAttrId,pbAttr,pcbAttrLen);
	else
		return -1;


	return stat;
}



WINSCARDAPI LONG WINAPI
SCardState2(
    IN SCARDHANDLE hCard,
    OUT LPDWORD pdwState,
    OUT LPDWORD pdwProtocol,
    OUT LPBYTE pbAtr,
    OUT LPDWORD pcbAtrLen)    
    {
        
	LONG stat= SCARD_S_SUCCESS ;
	int nb;
    char myreader[200];
	DWORD size=200;

	nb= isGridSc(&hCard);

    //!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    if (nb <= 0)
    // stat= SCARD_S_SUCCESS ;    
    //stat = SCardState(hCard,pdwState,pdwProtocol,pbAtr,pcbAtrLen);
    stat = SCardStatus(hCard,myreader,&size,pdwState,pdwProtocol,pbAtr,pcbAtrLen);

	else
	{ 
	sprintf(&atr[6],"%03d",nb);
    *pdwState    =  SCARD_STATE_PRESENT ;
    *pdwProtocol =  ptcol   ;
	*pcbAtrLen   = sizeof(atr)-1;
	 memmove(pbAtr,atr,sizeof(atr));
	}

return stat ;
}




