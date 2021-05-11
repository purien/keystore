/* pcsc.c */
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

#include "atr.h"

#include <winscard.h>
#ifndef WIN32
#include <reader.h>
#endif
#include "pcscemulator.h"
#include "mutuex.h"
#include "readers.h"


#define MIN(a,b) (((a)<(b))?(a):(b))

#define MAX_USER_NAME 128

#define SIZE_ATR_TABLE 64
int SizeAtrTable=0;
struct {  char atr[128]   ;
          char isd[64]    ;
       } AtrTable[SIZE_ATR_TABLE] ;


#define SIZE_TYPE_TABLE 64
int SizeTypeTable=0;
struct {  char type[128]   ;
       } TypeTable[SIZE_TYPE_TABLE]; 


#define SIZE_SNREADER_TABLE 64
int SizeSnReaderTable=0;
struct {  char sn[128]   ;
          char type[128] ;
		  int  both      ;
          int  seid      ;
       } SnReaderTable[SIZE_SNREADER_TABLE] ;


#define SIZE_SNCARD_TABLE 64
int SizeSnCardTable=0;
struct {  char sn[128]   ;
          int  seid      ;
       } SnCardTable[SIZE_SNCARD_TABLE]; 


#define MAX_USERS_TABLE       2000
#define MAX_AIDS_USERS_TABLE  2000


#define MAX_RESP   512
#define ATRLEN     MAX_RESP
#define MAX_SEID   1000
#define MAX_AID    1000

static char  Atr[MAX_READER][ATRLEN];
static int   AtrLen[ATRLEN];
static char  Reader_String[4096]     ;
static char *Reader_List [MAX_READER];
static int   Reader_Index_On[MAX_READER] ;
static int   Reader_Index_Abs[MAX_READER];
static char  listseid[8*MAX_SEID]              ;
static int   Reader_Lock[MAX_READER]           ;
static int   Reader_seid[MAX_READER]           ;
static int   Reader_aidline[MAX_READER]        ;
static int   Reader_aidline_index[MAX_READER]  ;
static int   iscard[MAX_READER]                ;



int SizeSeidTable=0;
struct {  int num_reader      ; // abs index
          char seid[64]       ;
       } SeidTable[MAX_SEID]  ;


int SizeAidTable=0;

struct {  int len             ;
          char aid[16]        ;
	   } AidTable[MAX_AID]    ;




static int   Reader_Nb = 0     ;
int   Reader_Nb_On = 0  ;


int GetListAttrib(int num_reader);
static int SanityCheck(SCARDCONTEXT *hContext,SCARDCONTEXT *hCard);

static int quit(int num_reader);
int start(int num_reader);
int close(int num_reader);

int StartAll();
int APDU(int num_reader,char *req, int sreq, char *resp, int *sresp);
int is_there_a_card(int num_reader);
int GetAtr(int num_reader,char ** atr);

char *Get_Reader_Name(int index_abs);
int  Get_Nb_Reader_On();
int  Get_Nb_Reader_Installed();
int  Get_Reader_Index_On(index_abs);
int  Get_Reader_Index_Abs(index_on);
int  Get_Nb_Selected_Reader();

int select_reader(int num_reader);



static int Ascii2bin(char *data_in,char *data_out);

int   indexs[MAX_READER]          ;
extern int gPrintf(int id,char *fmt, ...);
static int do_verbose=1;

extern int Ascii2bin(char *Data_In,char *data_out);

static int   UsersTable[MAX_USERS_TABLE];
static int   NbUsers=0;

static struct { char name[MAX_USER_NAME];
                int  nb;
		        int  iUsersTable; 
              } Users[64];


static int   AidsUsersTable[MAX_AIDS_USERS_TABLE]  ;
static int   FilterUsersTable[MAX_AIDS_USERS_TABLE];
static int   NbAidsUsers=0;

typedef struct { int index_aid       ;
	             int police          ;
				 int nb_users        ;
  			     int iAidsUsersTable ;
               } AIDLINE;

static struct { int police;
                int nb_aid;
		        AIDLINE aidline[8] ; 
			  } SeidsAids[MAX_SEID];

#define MAXAPDUFILTER 8096
static char ApduFilter[MAXAPDUFILTER];
static int  NbApduFilter=0;


int reader_no_seid(int num_reader)
{  	Reader_seid[num_reader] = -1         ;
	Reader_aidline[num_reader] = -1      ;
	Reader_aidline_index[num_reader] = -1;

	return 0;

}

int GetSeidList(int index, char *List, int size)
{ int i,num,first=1;

  num= Reader_Index_Abs[index];
  List[0]=0;

  for (i=0;i<SizeSeidTable;i++)
  {
  if (SeidTable[i].num_reader == num )
  { 
    if (first != 1)
		strcat(List,", ");
	else
		strcpy(List,"SEID: ");

    strcat(List,SeidTable[i].seid);
	first=0;
  }

  }

  return (int)strlen(List) ;

}


int pushseid(char *seid)
{ int i=0;

  for(i=0;i<SizeSeidTable;i++)
  { if ( strcmp(SeidTable[i].seid,seid)== 0 )
    return i;
  }

  strcpy(SeidTable[SizeSeidTable].seid,seid) ;
  SeidTable[SizeSeidTable].num_reader=-1     ;
  SizeSeidTable++;
  return SizeSeidTable-1;
}
 
int pushseid_d(int seid)
{ char v[14]="";
  int err;
  err = sprintf(v,"%d",seid);

  return pushseid(v);;
}

int getseidindex(char *seid)
{ int i;
     for(i=0;i<SizeSeidTable;i++)
    { if ( strcmp(SeidTable[i].seid,seid)==0 )
      return i;
	}
return -1;

  }


int pushaid(char *aid, int len)
{ int i=0;

  for(i=0;i<SizeAidTable;i++)
  { if ( (len == AidTable[i].len) && (memcmp(AidTable[i].aid,aid,len)==0) )
    return i;
  }

  memcpy(AidTable[SizeAidTable].aid,aid,len);
  AidTable[SizeAidTable].len= len;
  SizeAidTable++;
  return SizeAidTable-1;
}
 


int getaiddindex(char *aid, int len)
{ int i;
     for(i=0;i<SizeAidTable;i++)
    { if ( (len == AidTable[i].len) && (memcmp(AidTable[i].aid,aid,len)==0) )
      return i;
	}
return -1;

  }




int GetUserId(char *name)
{ int i;
  for (i=0;i<NbUsers;i++)
  { if (strcmp(Users[i].name,name)==0) 
  return i;
  }

  return -1;
}

///////////////////////////////////////////////////
char * get_seid(int uid,int index)
{ int seid; 
  if (uid == -1) return NULL;
  if (Users[uid].nb == -1) return NULL ;
  if (index > (Users[uid].nb-1)) return NULL;
  
  seid = UsersTable[Users[uid].iUsersTable+index] ;
  
  if (SeidTable[seid].num_reader != -1)
	  return SeidTable[seid].seid;
   
  return NULL;
}
//////////////////////////////////////////////////////////



int CheckSEID(char * SEID,int uid)
{ int i,seid; 

  if (uid == -1)
	  return -1;

  if (Users[uid].nb == -1)
  {  seid = getseidindex(SEID);
     if (seid < 0) return -1;
     return seid;
  }

  else
  { for (i=0;i<Users[uid].nb;i++)
    { seid = UsersTable[Users[uid].iUsersTable+i] ;
      if ( strcmp(SeidTable[seid].seid,SEID) ==0 )
      return seid;
    }
  }

  return -1;



  
}


int buildlistseid()
{ int i;

  listseid[0]=0;
  for(i=0;i<MAX_SEID;i++)
  { if (SeidTable[i].num_reader != -1)
    sprintf(&listseid[(int)strlen(listseid)],"%s ",SeidTable[i].seid);
  }

  return 0;
 
}



char* getlistseid()
{ return listseid;
}

int getlistmyseid(int uid, char * resp, int *len)
{ int i,seid; 
  
  resp[0]=0;

  if (uid == -1)
	  return -1;

  if (Users[uid].nb == -1)
  {  
	  sprintf(resp,"%s ",listseid);
  }

  else
  { for (i=0;i<Users[uid].nb;i++)
    { 
	  seid = UsersTable[Users[uid].iUsersTable+i] ;
      if (SeidTable[seid].num_reader != -1)
      sprintf(resp+((int)strlen(resp)),"%s ",SeidTable[seid].seid);
    }
  }

  *len = (*len) - ((int)strlen(resp)+1);
  
  return (int) strlen(resp);
  
}





int checkseid(char *id, int uid, int *seid)
{   int err;
	
    err= CheckSEID(id,uid);

	*seid= err;

	if (err <0) 
		return -1;

	return SeidTable[err].num_reader ;
		
}

int setlock(int num_reader, int sid)
{
   if (Reader_Lock[num_reader] == sid)
	  return 0;

   Reader_Lock[num_reader] = sid   ;
 
   reader_no_seid(num_reader);

   return 0;

 }




int check_and_set_lock(int num_reader, int sid)
{ 
  if (Reader_Lock[num_reader] == sid)
	  return 0;

  if (Reader_Lock[num_reader] == -1) 
    return 	setlock(num_reader,sid);


  return -1;
}



int apdu_firewall(char *apdu, int len, int uid, int seid)
{ int lena,i,stat=-1,k,index,profile,nb,j ;
  char mask[4],val[4];
	
    apdu[0] = apdu[0] & (char)0xFC ; //Reset Logical Channel

	// If no SELECT APDU
	if ( (apdu[0] != (char)0x00) ||  (apdu[1] != (char)0xA4) ||  (apdu[2] != (char)0x04) || (apdu[3] != (char)0x00) )
	{   
		if (Reader_seid[SeidTable[seid].num_reader] != seid) // no aid selected
			return -2;
		else
		{ index= Reader_aidline[SeidTable[seid].num_reader];
		  
		  if (index <0)
			  return 0; // no profile defined
		  else
		  { k= Reader_aidline_index[SeidTable[seid].num_reader];
			
		    profile = FilterUsersTable[k + SeidsAids[seid].aidline[index].iAidsUsersTable];

		    if (profile <0)
				return 0; // no profile defined
			else 
			{ // profile
            
            nb = 0xFF & ApduFilter[profile];
			
			if (nb <=0)
				return 0;

			j= profile + 1;

			for(i=0;i<nb;i++)
			{ mask[0]= ApduFilter[j++];
	          mask[1]= ApduFilter[j++];
	          mask[2]= ApduFilter[j++];
	          mask[3]= ApduFilter[j++];

              val[0]= ApduFilter[j++];
	          val[1]= ApduFilter[j++];
	          val[2]= ApduFilter[j++];
	          val[3]= ApduFilter[j++];

			  mask[0] = mask[0] & apdu[0];
              mask[1] = mask[1] & apdu[1];
              mask[2] = mask[2] & apdu[2];
              mask[3] = mask[3] & apdu[3];

			  if ((mask[0]==val[0]) && (mask[1]==val[1]) && (mask[2]==val[2]) && (mask[3]==val[3]) )
				  return -3;
			  
			}
		  }
		 }
		}

		return 0;
	}

    lena = apdu[4] & 0xFF ;


    
    for(i=0;i<SeidsAids[seid].nb_aid;i++)
	{

	if (SeidsAids[seid].aidline[i].index_aid == -1)  // default option
     { 
        for(k=0;k<SeidsAids[seid].aidline[i].nb_users;k++) // user list found for this aid, looking for user match
		{ if (AidsUsersTable[k + SeidsAids[seid].aidline[i].iAidsUsersTable] == uid)
		  { if (SeidsAids[seid].aidline[i].police == 1) 
		     stat=-1 ;
		    else                                        
			{   Reader_seid[SeidTable[seid].num_reader]   = seid      ;
                Reader_aidline[SeidTable[seid].num_reader]= i         ;
                Reader_aidline_index[SeidTable[seid].num_reader]= k   ;
               	stat=0  ;
		    }
			return stat;
		  }
		}
       
		// default option,  no user list found (0)
        if (SeidsAids[seid].aidline[i].police == 1) 
		{   Reader_seid[SeidTable[seid].num_reader]   = seid      ;
            Reader_aidline[SeidTable[seid].num_reader]= i         ;
            Reader_aidline_index[SeidTable[seid].num_reader]= -1  ;
			stat=0 ;
		}
        else stat=-1;  
		
		return stat;

	 }
		
	// no default option
	 else if ( ( lena == AidTable[SeidsAids[seid].aidline[i].index_aid].len) && (memcmp(AidTable[SeidsAids[seid].aidline[i].index_aid].aid,&apdu[5],lena)==0) )
	  { // AID match

        for(k=0;k<SeidsAids[seid].aidline[i].nb_users;k++) // user list, looking for match
		{ if (AidsUsersTable[k + SeidsAids[seid].aidline[i].iAidsUsersTable] == uid)
		  { if (SeidsAids[seid].aidline[i].police == 1) 
		     stat=-1 ;
		    
		    else   // seid, aidline= i;
			{   Reader_seid[SeidTable[seid].num_reader]   = seid      ;
		        Reader_aidline[SeidTable[seid].num_reader]= i         ;
                Reader_aidline_index[SeidTable[seid].num_reader]= k   ;
				stat=0  ;
		    }
			return stat;
		  }
		}

        // no user list found
		if (SeidsAids[seid].aidline[i].police == 1) 
		{   Reader_seid[SeidTable[seid].num_reader]   = seid       ;
            Reader_aidline[SeidTable[seid].num_reader]= -1         ;
            Reader_aidline_index[SeidTable[seid].num_reader]= -1   ; 
			stat=0 ;
           
		}
        else   
			stat=-1; 

		return stat;


	  }
	}

    // Default Behavior

    if (SeidsAids[seid].police == 1)  
	{ Reader_seid[SeidTable[seid].num_reader]   = seid ;
   	  Reader_aidline[SeidTable[seid].num_reader]= -1         ;
      Reader_aidline_index[SeidTable[seid].num_reader]= -1   ;    
	  stat=0 ;
	}
	else 
		stat=-1;  


	return stat;
}

extern char gridserver[] ;
extern int  maxslots     ;
extern int  startslot    ;
extern char board[]      ;
extern unsigned short gridport;


extern char mysocket[];
extern int  stimeout;

extern int autostart;
int default_se_access=1;
extern int racs_verbose;
extern int is_external_grid;


int secure_element_index=1;
extern int verbose2;
extern int reader_console ;
extern int system_console ;
extern int racs_log;

extern int NC;
extern int wBG ;
extern int wPEN;
extern int wSIZE;

extern int close_session_console ;
extern int close_session_delay   ;
extern int session_console_tile;


extern char strace[]   ;
extern int startdelay;


int restricted_seid_list=0;


int emptyline(char *line)
{ char line2[1024];
  char *token= NULL;
  
  strcpy(line2,line);
 
  token = strtok(line2," \r\n"); 
  if (token == NULL)  // for example 20 20 20 CR LF returns NULL
	  return 1;

  if (*token == (char)'/')
	  return 1;

  if (*token == (char)'*')
     return 1;

	 return 0;


}

extern int Ascii2bin(char *data_in,char *data_out);



int ReadAllTables(char *base)
{ FILE *f=NULL,*f2=NULL;
  int nb,ict,i,more=0,x=0,nc=0,nba=0,index=0,k,v,kk;
  char line[1024],line2[1024],*token,*token2;
  char seid_s[128];
  char rep_base[128]= "./config/";
  char rep_f[256] ;
  char aid[16];
  int aid_len=0,aid_index;
  char *opt;
  int j;
  
  if (base == NULL);
  else strcpy(rep_base,base);
	 

   for (i=0;i<MAX_SEID;i++) 
   { SeidTable[i].num_reader= -1;
     SeidTable[i].seid[0] = 0;

     SeidsAids[i].police  = default_se_access;
     SeidsAids[i].nb_aid  = 0;
   }

 strcpy(rep_f,rep_base)    ;
 strcat(rep_f,"config.txt");
 f = fopen(rep_f,"rt")     ;

     if (f!= NULL)
	 { 
	 
	 for(;;)
	 {
     if (fgets(line,1024,f)== NULL)  break;  // 0x0A=LF is included
	 if (line[(int)strlen(line)-1] == '\n' ) line[(int)strlen(line)-1]=0;
     if (emptyline(line)==1) continue; // comment or empty line
 
     token = strtok(line," \r\n"); 
	 if (token == NULL) continue;
     opt=token;
	
     token = strtok(NULL," \r\n");
	 if (token == NULL) break;

	 else if (strcmp(opt,"trace_dir") == 0)
		 strcpy(strace,token);

     else if (strcmp(opt,"start_delay") == 0)
	 { nb=sscanf(token,"%d",&v);
	   if (nb == 1) startdelay=v ;
	 }

     else if (strcmp(opt,"server_port") == 0)
		 strcpy(mysocket,token);

     else if (strcmp(opt,"server_timeout") == 0)
	 { nb=sscanf(token,"%d",&v);
	   if (nb == 1) stimeout=v ;
	 }

     else if (strcmp(opt,"autostart") == 0)
	 { if (strcmp(token,"yes") ==0) autostart=1;
	   else                         autostart=0;
	 }

     else if (strcmp(opt,"se_default_access") == 0)
	 { if (strcmp(token,"yes") ==0) default_se_access=1;
	   else                         default_se_access=0;
	 }

     else if (strcmp(opt,"restricted_seid_list") == 0)
	 { if (strcmp(token,"yes") ==0) restricted_seid_list=1;
	   else                         restricted_seid_list=0;
	 }

     else if (strcmp(opt,"session_console_tile") == 0)
	 { if (strcmp(token,"yes") ==0) session_console_tile=1;
	   else                         session_console_tile=0;
	 }


    else if (strcmp(opt,"grid_server") == 0)
		 strcpy(gridserver,token);

    else if (strcmp(opt,"grid_port") == 0)
	 { nb=sscanf(token,"%d",&v);
	   if (nb == 1) gridport= (unsigned short) (v & 0xFFFF);
	 }

    else if (strcmp(opt,"grid_board") == 0)
		 strcpy(board,token);

     else if (strcmp(opt,"grid_first_slot") == 0)
	 { nb=sscanf(token,"%d",&v);
	   if (nb == 1) startslot=v-1 ;
	 }

     else if (strcmp(opt,"grid_max_slots") == 0)
	 { nb=sscanf(token,"%d",&v);
	   if (nb == 1) maxslots=v ;
	 }
     
	 else if (strcmp(opt,"racs_verbose") == 0)
	 { if (strcmp(token,"yes") ==0) racs_verbose=1;
	   else                         racs_verbose=0;
	 }

	 else if (strcmp(opt,"is_external_grid") == 0)
	 { if (strcmp(token,"yes") ==0) is_external_grid=1;
	   else                         is_external_grid=0;
	 }

	 else if (strcmp(opt,"secure_element_index") == 0)
	 { if (strcmp(token,"yes") ==0) secure_element_index=1;
	   else                         secure_element_index=0;
	 }

	 else if (strcmp(opt,"reader_verbose") == 0)
	 { if (strcmp(token,"yes") ==0) verbose2=do_verbose=1;
	   else                         verbose2=do_verbose=0;
	 }

	 else if (strcmp(opt,"reader_console") == 0)
	 { if (strcmp(token,"yes") ==0) reader_console=1;
	   else                         reader_console=0;
	 }

	 else if (strcmp(opt,"system_console") == 0)
	 { if (strcmp(token,"yes") ==0) system_console=1;
	   else                         system_console=0;
	 }


	 else if (strcmp(opt,"line_size") == 0)
	 {  nb=sscanf(token,"%d",&v);
	   if (nb == 1) NC= v;
	 }

	 else if  (strcmp(opt,"font_size") == 0)
	 {  nb=sscanf(token,"%d",&v);
	   if (nb == 1) wSIZE=v;
	 }

	 else if (strcmp(opt,"bg_color") == 0)
	 {  nb=sscanf(token,"%x",&v);
	   if (nb == 1) wBG=v;
	 }

	 else if (strcmp(opt,"pen_color") == 0)
	 {  nb=sscanf(token,"%x",&v);
	   if (nb == 1) wPEN=v;
	 }

     else if (strcmp(opt,"close_session_console") == 0)
	 { if (strcmp(token,"yes") ==0) close_session_console=1;
	   else                         close_session_console=0;
	 }

	 else if (strcmp(opt,"close_session_delay") == 0)
	 {  nb=sscanf(token,"%d",&v);
	   if (nb == 1) close_session_delay= v;
	 }


     else if (strcmp(opt,"racs_log") == 0)
	 { if (strcmp(token,"yes") ==0) racs_log=1;
	   else                         racs_log=0;
	 }
     

	 } // End For

	fclose(f);

	if (is_external_grid==0) maxslots=0;
    }

 for(i=0;i<MAX_USERS_TABLE;i++) UsersTable[i]= -1;

 strcpy(rep_f,rep_base)    ;
 strcat(rep_f,"users.txt");

 f = fopen(rep_f,"rt");

     if (f!= NULL)
	 { ict=0;index=0;
	 
	 for(;;)
	 {
     if (fgets(line,1024,f)== NULL)  break;
	 if (line[(int)strlen(line)-1] == '\n' ) line[(int)strlen(line)-1]=0;
     if (emptyline(line)==1) continue; // comment or empty line    
         
	 Users[ict].name[0]=0;
     Users[ict].iUsersTable = -1;
     Users[ict].nb=0;

	 nba=0;
     token = strtok(line," \r\n"); 
	 if (token == NULL) continue;

     nb=sscanf(token,"%s",Users[ict].name);
	 if (nb != 1) break;
     token = strtok(NULL," \r\n");
	 if (token == NULL) break;

	 if (strcmp(token,"all")==0)
	 Users[ict].nb=-1;

	 else
	 { nb=sscanf(token,"%d",&Users[ict].nb);
	   if (nb != 1)    break;
     }

     nba=Users[ict].nb;
  	 ict++;    

	 if (nba == -1) 
		 continue;

	 else {

     Users[ict-1].iUsersTable = index; 
    
	 for(i=0;i<nba;i++)
	 { token = strtok(NULL," \r\n");
	   if (token == NULL) {i=nba;continue;}
       UsersTable[index+i]= pushseid(token);
	   if (nb != 1) {i=nba;continue;}
	 }

	 index += nba;
	 }


    
	 } // End For

	 NbUsers=ict;
	 fclose(f);
     }

   strcpy(rep_f,rep_base)    ;
   strcat(rep_f,"atr.txt")   ; 

   f = fopen(rep_f,"rt");

     if (f!= NULL)
	 { ict=0;
	  for(;;)
	 { nb=0;
	   if (fgets(line,128,f)== NULL)  break;
	   if (line[(int)strlen(line)-1] == '\n' ) line[(int)strlen(line)-1]=0;
       if (emptyline(line)==1) continue; // comment or empty line      
	   else 
		   nb=sscanf(line,"%s %s",AtrTable[ict].atr,AtrTable[ict].isd);
	   if (nb != 2) 
		   break;
	   ict++;
	 } 
	 SizeAtrTable=ict;
	 fclose(f);
     }

 strcpy(rep_f,rep_base)  ;
 strcat(rep_f,"type.txt");

 f = fopen(rep_f,"rt");

     if (f!= NULL)
	 { ict=0;
	  for(;;)
	 { if (fgets(line,128,f)== NULL)  break;
       if (line[(int)strlen(line)-1] == '\n' ) line[(int)strlen(line)-1]=0;
       if (emptyline(line)==1) continue; // comment or empty line
	   else 
	   { strcpy(TypeTable[ict].type,line);
         token = strtok(line,"\"\r\n"); 
	     if (token != NULL) 
			strcpy(TypeTable[ict].type,token); ;
	   }
	   ict++;
	 } 
	 SizeTypeTable=ict;
	 fclose(f);
     }

 strcpy(rep_f,rep_base)      ;
 strcat(rep_f,"readersn.txt");

 f = fopen(rep_f,"rt");

     if (f!= NULL)
	 { ict=0;
	  for(;;)
	 { nb=0;
	   if (fgets(line,256,f)== NULL)  break;
       if (line[(int)strlen(line)-1] == '\n' ) line[(int)strlen(line)-1]=0;
       if (emptyline(line)==1) continue; // comment or empty line
	   else  
	   nb=sscanf(line,"%s %s",SnReaderTable[ict].sn,seid_s);
           
	  if (nb != 2) break;

      SnReaderTable[ict].seid = pushseid(seid_s);
      SnReaderTable[ict].both=0;
      SnReaderTable[ict].type[0] = 0;
     

	  token = strtok(line," \r\n"); 
	  if (token != NULL) // Serial Number
	  {  token = strtok(NULL," \r\n"); 
		 if (token != NULL)  //SEID
		 {
         token = strtok(NULL,"\""); 
	      if (token != NULL)  // "Type"
	      {	strcpy(SnReaderTable[ict].type,token); 
	        SnReaderTable[ict].both=1;
	      }
		 }
	  }

	  ict++;
	 } 
	 SizeSnReaderTable=ict;
	 fclose(f);
     }

 strcpy(rep_f,rep_base)    ;
 strcat(rep_f,"cardsn.txt");

 f = fopen(rep_f,"rt");

     if (f!= NULL)
	 { ict=0;
	  for(;;)
	 { nb=0;
	   if (fgets(line,128,f)== NULL)  break;
       if (line[(int)strlen(line)-1] == '\n' ) line[(int)strlen(line)-1]=0;
       if (emptyline(line)==1) continue; // comment or empty line
	   else 
	   nb=sscanf(line,"%s %s",SnCardTable[ict].sn,seid_s);

   	   if (nb != 2) break;
       
	   SnCardTable[ict].seid = pushseid(seid_s);
	 
	   ict++;
	 } 
	 SizeSnCardTable=ict;
	 fclose(f);
     }

///////////////////////////////////////
index=0; // Index de base dans AidsUsersTable et FilterUsersTable
for(i=0;i<SizeSeidTable;i++)
{ strcpy(seid_s,SeidTable[i].seid);
  strcat(seid_s,".txt") ;

  strcpy(rep_f,rep_base);
  strcat(rep_f,seid_s);

  f = fopen(rep_f,"rt");

  if (f!= NULL)
  {  for(;;)
	 {
     if (fgets(line,1024,f)== NULL)  break;
	 if (line[(int)strlen(line)-1] == '\n' ) line[(int)strlen(line)-1]=0;
	 if (emptyline(line)==1) continue; // comment or empty line

	 nba=0;
     token = strtok(line," \r\n"); 
	 if (token == NULL) continue ;

	 if (strcmp(token,"default") == 0) // wildcard
	 { aid_index=-1;
	 }

	 else
     {
	 if (strlen(token) > 32)
		 break;

	 aid_len = Ascii2bin(token,aid);
	 
	 if (aid_len <=0 )
		 break;

     aid_index= pushaid(aid,aid_len) ;
     }

	 SeidsAids[i].aidline[SeidsAids[i].nb_aid].police=0;
     SeidsAids[i].aidline[SeidsAids[i].nb_aid].index_aid= aid_index;
     SeidsAids[i].aidline[SeidsAids[i].nb_aid].nb_users=0;
 

     token = strtok(NULL," \r\n"); 
	 if (token == NULL) break    ;

	 if (strcmp(token,"yes")==0)
     SeidsAids[i].aidline[SeidsAids[i].nb_aid].police=1;
	 else
     SeidsAids[i].aidline[SeidsAids[i].nb_aid].police=0;


     token = strtok(NULL," \r\n");
	 if (token == NULL) break;
     nb=sscanf(token,"%d",&nba);
	 if (nb != 1) 
		 break ;
     
     SeidsAids[i].aidline[SeidsAids[i].nb_aid].nb_users = nba;
	 
	 if (nba == 0)
	 { // SeidsAids[i].nb_aid++;
       // continue ;
	 }
	 
	 else
	 {
	 SeidsAids[i].aidline[SeidsAids[i].nb_aid].iAidsUsersTable = index; 
      
	 ict=0; // user counter

	 for(k=0;k<nba;k++)
	 { token = strtok(token+strlen(token)+1," \r\n");

       if (token == NULL) //{k=nba;continue;}
		   break;

	   strcpy(line2,token);
       token2=NULL;
	   for(j=0;j<(int)strlen(line2);j++)
	   { if (line2[j] == (char)':')
	     { token2= line2+ j+1;
	       line2[j]=0;
		   break;
	     }
	   }

	   nb = GetUserId(line2);
	   if (nb<0)  continue  ;

       
	   AidsUsersTable[index+ict]  = nb ; 
       FilterUsersTable[index+ict]= -1 ; 

	 //==================profile=reading=======================
  	 if ( (token2 != NULL) && (SeidsAids[i].aidline[SeidsAids[i].nb_aid].police==0) )
	 {  strcpy(rep_f,rep_base);
        strcat(rep_f,token2);

		f2 = fopen(rep_f,"rt"); //opening Apdu Filter File
        if (f2 != NULL)
	    { 
		nc=0;
	    for(;;)
	    {
        if (fgets(line2,1024,f2)== NULL)  break;  // 0x0A=LF is included
	    if (line2[(int)strlen(line2)-1] == '\n' ) line2[(int)strlen(line2)-1]=0;
        if (emptyline(line2)==1) continue; // comment or empty line

		nb= Ascii2bin(line2,&ApduFilter[NbApduFilter+1+8*nc]);
		if (nb != 8)
			continue;
		nc++;
		}

        fclose(f2);

		// APDU Filter Compression
		j=0;
		kk=NbApduFilter;
        while (j<NbApduFilter)
		{ nb= 0xFF & ApduFilter[j];
		  if (nb == nc)
		  { if (memcmp(&ApduFilter[j+1], &ApduFilter[NbApduFilter+1],8*nc)==0)
		    {  kk=j; break; }
		  }
          j+= (1+8*nb);
		}
        
	    if (nc >0)
		{ //SeidsAids[i].aidline[SeidsAids[i].nb_aid].profile= k;
		  FilterUsersTable[index+ict]= kk ;
		  if (kk==NbApduFilter)
		  {	ApduFilter[NbApduFilter]=nc;
		    NbApduFilter += (1+8*nc)   ;
		  }
		}


		} // end of FILE *f2 not NULL
	 }
	 // ===========end=of=profile=reading===============================
	   
	 
	 ict++;
     
	 }

	 index += ict;
     SeidsAids[i].aidline[SeidsAids[i].nb_aid].nb_users = ict;
     //SeidsAids[i].nb_aid++;
	 }

     SeidsAids[i].nb_aid++;
     
	 } // End for(;;) seid.txt parser


	 NbAidsUsers = index; 
	 fclose(f);
     }

	 }// next SEID file


return(0);



}


int is_there_a_card(num_reader)
{ return (iscard[num_reader]);
}

int GetAtr(int num_reader, char ** atr)
{ *atr= Atr[num_reader];
  return AtrLen[num_reader] ;
}

static SCARDCONTEXT hContext[MAX_READER];//=(SCARDCONTEXT)NULL;
static SCARDHANDLE hCard[MAX_READER];//    =(SCARDCONTEXT)NULL;
static DWORD dwScope[MAX_READER];//= (DWORD)SCARD_SCOPE_SYSTEM;
static DWORD dwState[MAX_READER],dwProtocol[MAX_READER],dwActiveProtocol[MAX_READER];

static LPCVOID pvReserved1=  (LPCVOID) NULL;
static LPCVOID pvReserved2=  (LPCVOID) NULL;
//static DWORD dwReaders;

char * Get_Reader_Name(int index_abs)
{ if(index_abs >= Reader_Nb) return NULL;
  return Reader_List[index_abs];
}

int Get_Nb_Reader_On()
{ return Reader_Nb_On ;
}


int Get_Nb_Reader_Installed()
{ return Reader_Nb ;
}

int Get_Reader_Index_On(index_abs)
{   if(index_abs >= Reader_Nb) return -1;
	return Reader_Index_On[index_abs];
}


int Get_Reader_Index_Abs(index_on)
{   if(index_on >= Reader_Nb_On) return -1;
	return Reader_Index_Abs[index_on];
}




int getcardsn(int num_reader, char *isd, char *sn)
{ char initialize[13] = {(char)0x80,(char)0x50,(char)0x00,(char)0x00,(char)0x08,(char)0x01,(char)0x23,(char)0x45,(char)0x67,(char)0x89,(char)0xAB,(char)0xCD,(char)0xEF};
  int err,sapdu;
  char apdu_req[300];
  char apdu_resp[300];
  int i;

  for(i=0;i<8;i++)
   initialize[5+i]  = rand() % 256;

  apdu_req[0]=(char)0x00;apdu_req[1]=(char)0xA4;apdu_req[2]=(char)0x04;apdu_req[3]=apdu_req[4]=(char)0;
  err= Ascii2bin(isd,&apdu_req[5]);
  apdu_req[4]=err;
  
  sapdu= (int)sizeof(apdu_resp);
  err=APDU(num_reader,apdu_req, 5+err, apdu_resp,&sapdu);

  

  if (err == 0)
  { 
	if ( (sapdu == 2) && ( (apdu_resp[0] != (char)0x90) || (apdu_resp[0] != (char)0x00) ) )
		return -1;
	  
	  
	sapdu= (int)sizeof(apdu_resp);
	err = APDU(num_reader,initialize,13, apdu_resp,&sapdu);
    if (err == 0)
	{ sn[0]=0;
      
	 if ( (sapdu >= 2) && ( (apdu_resp[sapdu-2] != (char)0x90) || (apdu_resp[sapdu-1] != (char)0x00) ) )
		return -1;

	  for(i=0;i<MIN(10,sapdu);i++)
	  sprintf(&sn[strlen(sn)],"%2.2X",(int)(0xFF & apdu_resp[i]));
	  return (0);
	}
  }

return -1;
}

int isAtr(char *atr, int atrlen)
{ char Atr[256];
  int i;

  Atr[0]=0;

  for(i=0;i<atrlen;i++)
	  sprintf(&Atr[strlen(Atr)],"%2.2X",0xFF & atr[i]);

  for(i=0;i<SizeAtrTable;i++)
  { if (strcmp(AtrTable[i].atr,Atr) == 0)
    return i;
  }
 
 return -1;
}

int isType(char *type)
{ 
  int i;
 
  for(i=0;i<SizeTypeTable;i++)
  { if (strcmp(TypeTable[i].type,type) == 0)
    return i;
  }
 
 return -1;
}


int isSnCard(char *sn)
{ int i;

 for(i=0;i<SizeSnCardTable;i++)
  { if (strcmp(SnCardTable[i].sn,sn) == 0)
    return i;
  }
 
 return -1;
}

int isSnReader(char *sn, char *type)
{ int i;

 for(i=0;i<SizeSnReaderTable;i++)
  { if (strcmp(SnReaderTable[i].sn,sn) == 0)
   {   if ( (SnReaderTable[i].both == 1) && (strcmp(SnReaderTable[i].type,type) != 0) );
	   else
		   return i;
   }
  }
 
 return -1;
}

 int _powerdown(int num_reader, int sid);

int powerdown(int num_reader, int sid)
{ int err;

  MUTEX_LOCK(Pmutex[M_READER+num_reader]);
  err= _powerdown(num_reader,sid);
  MUTEX_UNLOCK(Pmutex[M_READER+num_reader]);

  return err;
}

int _powerdown(int num_reader, int sid)
{ LONG stat ;   
  
   if (Reader_Nb_On <= 0)
		return -1 ;

    if (hCard [num_reader]   != (SCARDCONTEXT)NULL) 
	stat = SCardDisconnect2(hCard[num_reader],(DWORD) SCARD_UNPOWER_CARD ) ;
	
	if (hContext[num_reader] != (SCARDCONTEXT)NULL) 
	stat = SCardReleaseContext2(hContext[num_reader]);
    
    iscard[num_reader]=0;

    hCard [num_reader]   = (SCARDCONTEXT)NULL;
    hContext[num_reader] = (SCARDCONTEXT)NULL;

    Reader_Lock[num_reader] = -1         ;
    reader_no_seid(num_reader)           ;

    if (do_verbose)	
	gPrintf(indexs[num_reader],"Reader %s is powerdown(sid=%d)...\n",Reader_List[num_reader],sid);

   return 0 ;
}

int closeseid(int sid)
{ int i,nb=0;

	for(i=0;i<Reader_Nb_On;i++)
	{	if (Reader_Lock[Reader_Index_Abs[i]] == sid)
		{ 	powerdown(Reader_Index_Abs[i],sid); nb++;}
	}

return nb ;
}


int _powerup(int num_reader, int sid);

int powerup(int num_reader, int sid)
{ int err;
	
  MUTEX_LOCK(Pmutex[M_READER+num_reader]);
  err= _powerup(num_reader,sid);
  MUTEX_UNLOCK(Pmutex[M_READER+num_reader]);
 

  return err;
}

int _powerup(int num_reader, int sid)
{ LONG stat ;
  int i;
  
  if (Reader_Nb_On <=0) 
		 return -1 ;

  if (check_and_set_lock(num_reader,sid) != 0)
	  return -2;
 
   if (iscard[num_reader]==1) 
	   return 2 ;

  	hContext[num_reader]=(SCARDCONTEXT)NULL ;
	stat = SCardEstablishContext2(dwScope[num_reader], pvReserved1, pvReserved2,&hContext[num_reader]);
		
	if (stat  != SCARD_S_SUCCESS) 
	{ quit(num_reader)     ;
	  return(-1)           ;
	}
	    
	 hCard[num_reader]=(SCARDCONTEXT)NULL ;
		
		stat = SCardConnectA2(hContext[num_reader],Reader_List[num_reader],
			(DWORD)SCARD_SHARE_EXCLUSIVE,
			(DWORD)(SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1),
			&hCard[num_reader],
			&dwActiveProtocol[num_reader]);
		
	

		if (stat != SCARD_S_SUCCESS) 
		{   quit(num_reader) ;
	     	return(-1);
		}

        if (do_verbose)	
			gPrintf(indexs[num_reader],"Reader %s is powerup (sid=%d)...\n",Reader_List[num_reader],sid);

		AtrLen[num_reader]= ATRLEN;

		stat = SCardState2(hCard[num_reader], &dwState[num_reader], &dwActiveProtocol[num_reader], Atr[num_reader], &AtrLen[num_reader]);

		if ((stat != SCARD_S_SUCCESS) || (dwState[num_reader] == SCARD_ABSENT))  
			return(-1);
		
		if (do_verbose)
		{
			gPrintf(indexs[num_reader],"ATR:");
			for (i=0;i<AtrLen[num_reader];i++)
				gPrintf(indexs[num_reader],"%02X ",0xff & Atr[num_reader][i]);
          gPrintf(indexs[num_reader],"\n");
		}


    iscard[num_reader]=1      ;
    reader_no_seid(num_reader);

    return 0 ;

}







// opt=0 cold, 1=warm
int _cardreset(int num_reader, int opt, int sid);

int cardreset(int num_reader,int opt, int sid)
{ int err;

  MUTEX_LOCK(Pmutex[M_READER+num_reader]);
  err= _cardreset(num_reader,opt,sid);
  MUTEX_UNLOCK(Pmutex[M_READER+num_reader]);
  
  return err;
}

int _cardreset(int num_reader, int opt, int sid)
{ LONG stat;

   if (Reader_Nb_On <=0) 
		 return -1 ;

   if (check_and_set_lock(num_reader,sid) != 0)
	  return -2;
 
    if (!iscard[num_reader]) 
		return -3;

    iscard[num_reader]=0; 

	if (opt==1)
	stat= SCardReconnect2(hCard[num_reader],(DWORD)SCARD_SHARE_EXCLUSIVE,dwActiveProtocol[num_reader],(DWORD)SCARD_RESET_CARD,&dwActiveProtocol[num_reader]);
	else
	stat= SCardReconnect2(hCard[num_reader],(DWORD)SCARD_SHARE_EXCLUSIVE,dwActiveProtocol[num_reader],(DWORD)SCARD_UNPOWER_CARD,&dwActiveProtocol[num_reader]);


	if (stat != SCARD_S_SUCCESS) 
		return -1 ;

	AtrLen[num_reader] = ATRLEN;
	
	stat = SCardState2(hCard[num_reader], &dwState[num_reader], &dwActiveProtocol[num_reader], Atr[num_reader], &AtrLen[num_reader]);
		
	if ((stat != SCARD_S_SUCCESS) || (dwState[num_reader] == SCARD_ABSENT))  
		return -1 ;

	iscard[num_reader]=1 ;

    if (do_verbose)	
	gPrintf(indexs[num_reader],"Reader %s reset (sid=%d)...\n",Reader_List[num_reader],sid);


    return 0;
}


char * FindSN(char* name)
{ int i,j,k,len;
  static char sn[200] ;
  
  len = (int)strlen(name);
  
  for (i=0;i<len;i++)
      if (name[i]== (char)'(' ) break;
      
  if (i == len) 
   return NULL;
  
  k=0;
  
    for (j=i+1;j<len;j++)
    {
        if (name[j] == (char)0x20)
            sn[k++] = (char)'-' ;
        
        else if (name[j] == (char)')' )
            break;
            
        else sn[k++]= name[j] ;
        
    }
   
   if (j == len)  
       return NULL; 
       
       sn[k]=0;
       
       return sn;
       
    
}

int start(int num_reader)
{ 	char *pname=Reader_String;
	DWORD dwReaders;
    LONG stat;
	int i,err;
    DWORD tsize;
	char sn[128], type[128], vendor[128];
    char *ptsn;
	int nh;
    ifd_atr_info_t info;
    
    sn[0]=type[0]=vendor[0]=0;
	
	iscard[num_reader]=0;
    /////////////////////////////////////////
    dwScope[num_reader] = SCARD_SCOPE_SYSTEM;

	if (Reader_Nb <=0) return -1 ;
		
	if (hCard [num_reader]   != (SCARDCONTEXT)NULL) stat = SCardDisconnect2(hCard[num_reader],(DWORD)SCARD_UNPOWER_CARD) ;
	if (hContext[num_reader] != (SCARDCONTEXT)NULL) stat = SCardReleaseContext2(hContext[num_reader]);

	dwReaders = sizeof(Reader_String);

	hContext[num_reader]=(SCARDCONTEXT)NULL ;
	stat = SCardEstablishContext2(dwScope[num_reader], pvReserved1, pvReserved2, &hContext[num_reader]);
		
		if (stat  != SCARD_S_SUCCESS) 
		{ quit(num_reader)     ;
		  return(-1);
		}
	    
	    hCard[num_reader]=(SCARDCONTEXT)NULL ;
        dwActiveProtocol[num_reader]=0;
		
		stat = SCardConnectA2(hContext[num_reader],(LPTSTR)Reader_List[num_reader],
			(DWORD)SCARD_SHARE_SHARED,//(DWORD)SCARD_SHARE_EXCLUSIVE,
			(DWORD)(SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1),
			&hCard[num_reader],
			&dwActiveProtocol[num_reader]);
		
		if (stat != SCARD_S_SUCCESS) 
			return(-1);

        ////////////COLD RESET ////////////////
	stat= SCardReconnect2(hCard[num_reader],
        (DWORD)SCARD_SHARE_EXCLUSIVE,
        dwActiveProtocol[num_reader],
        (DWORD)SCARD_RESET_CARD,
        &dwActiveProtocol[num_reader]);

        if (stat != SCARD_S_SUCCESS) 
			return(-1);


         /////////////////WARM RESET/////////////
	stat= SCardReconnect2(hCard[num_reader],
        (DWORD)SCARD_SHARE_EXCLUSIVE,
        dwActiveProtocol[num_reader],
        (DWORD)SCARD_UNPOWER_CARD,
        &dwActiveProtocol[num_reader]);
        
		if (stat != SCARD_S_SUCCESS) 
			return(-1);

		if (do_verbose)	
			gPrintf(indexs[num_reader],"Reader %s is powered on...\n",Reader_List[num_reader]);

		AtrLen[num_reader]= ATRLEN;

		stat = SCardState2(hCard[num_reader], &dwState[num_reader], &dwActiveProtocol[num_reader], Atr[num_reader], &AtrLen[num_reader]);

		if ((stat != SCARD_S_SUCCESS) || (dwState[num_reader] == SCARD_ABSENT))  
			return(-1);
		
		if (do_verbose)
		{
			gPrintf(indexs[num_reader],"ATR:");
			for (i=0;i<AtrLen[num_reader];i++)
				gPrintf(indexs[num_reader],"%02X ",0xff & Atr[num_reader][i]);
          gPrintf(indexs[num_reader],"\n");
		}

       iscard[num_reader]=1;

	   vendor[0]=type[0]=sn[0]=0;
	   tsize= (DWORD)(sizeof(vendor)-1) ;
	   
       stat= SCardGetAttrib2(hCard[num_reader],SCARD_ATTR_VENDOR_NAME,(LPBYTE)vendor,&tsize);
       if (stat == SCARD_S_SUCCESS) vendor[(int)tsize]=0;
       if (do_verbose && (stat ==  SCARD_S_SUCCESS) )
		   gPrintf(indexs[num_reader],"Vendor: %s\n",vendor);
			  
       if (stat == SCARD_S_SUCCESS)
       { tsize = (DWORD)(sizeof(type)-1);
         stat= SCardGetAttrib2(hCard[num_reader],SCARD_ATTR_VENDOR_IFD_TYPE,(LPBYTE)type,&tsize);
         if (stat == SCARD_S_SUCCESS) type[(int)tsize]=0;
         
       
       if (stat != SCARD_S_SUCCESS)
       { strcpy(type,vendor)   ;
         //strcpy(type,Reader_List[num_reader]);
         stat = SCARD_S_SUCCESS;
         gPrintf(indexs[num_reader],"$");
       }
       
       if (do_verbose && (stat ==  SCARD_S_SUCCESS) )
		   gPrintf(indexs[num_reader],"Type: %s\n",type);
       }

	
       
       if (stat == SCARD_S_SUCCESS)
       {  
       tsize = (DWORD)(sizeof(sn)-1);
       stat= SCardGetAttrib2(hCard[num_reader],SCARD_ATTR_VENDOR_IFD_SERIAL_NO,(LPBYTE)sn,&tsize);
       if (stat == SCARD_S_SUCCESS) sn[(int)tsize]=0;
       
       if (stat != SCARD_S_SUCCESS)
       { ptsn = FindSN(Reader_List[num_reader]) ;
         if (ptsn != NULL)
         { strcpy(sn,ptsn);
           stat = SCARD_S_SUCCESS;
           gPrintf(indexs[num_reader],"$");
         }
       }
       
       if (do_verbose && (stat ==  SCARD_S_SUCCESS) )
	   gPrintf(indexs[num_reader],"SN: %s\n",sn);
       }
		
	  
	   if ( (type[0] != 0) && (isType(type)>=0) )
	     { err = isSnReader(sn,type);
	       if ( (err >=0) && (SnReaderTable[err].seid >=0) && (SnReaderTable[err].seid < MAX_SEID)  )
		   {   SeidTable[SnReaderTable[err].seid].num_reader = num_reader;
               gPrintf(0,"SEID= %s, for reader# %03d, ReaderSN= %s\n",SeidTable[SnReaderTable[err].seid].seid,Reader_Index_On[num_reader],sn);
	 	   }
	     }

       /////////////////////////////////////////////////
	   err= isAtr(Atr[num_reader],AtrLen[num_reader]) ;
	   err=0; // we don't need to check the ATR table

	   if (err >=0)
	   { // err = getcardsn(num_reader,AtrTable[err].isd,sn);  
		 err= ifd_atr_parse(&info, (unsigned char *)Atr[num_reader], (unsigned int)AtrLen[num_reader]);
         if(err >=0)
		 { nh = Atr[num_reader][1] & 0xF ;
	       memmove(sn,Atr[num_reader]+AtrLen[num_reader]-nh-err,nh);
	       sn[nh]=0;
          /////////////////////////////////////////////////
		 }

	     if (err >=0)
		 {
		 err = isSnCard(sn);
		 if ( (err >=0) && (SnCardTable[err].seid >=0) && (SnCardTable[err].seid < MAX_SEID ) )
		 {    
			   SeidTable[SnCardTable[err].seid].num_reader = num_reader;
               gPrintf(0,"SEID= %s, for reader# %03d, CardSN=   %s\n",SeidTable[SnCardTable[err].seid].seid,Reader_Index_On[num_reader],sn);
		 }

		 }
	   }

      // SCARD_ATTR_VENDOR_IFD_VERSION
       powerdown(num_reader,-1);
		


return (stat);
}

int close(int num_reader)
{ int stat;

     if (!iscard[num_reader])
		 return -1;

     stat= quit(num_reader) ;
	 return(0);
}


int CloseAll()
{ int i;
	
  for(i=0;i<Reader_Nb_On;i++)
	  close(Reader_Index_Abs[i]) ;

  return Reader_Nb_On;
}
extern int NBSC;      // number of grid activated SE  from startslot to startslot+mawslots-1
extern int maxslots ; // number of slot
extern int startslot; // number of the first slot

int StartAll()
{	SCARDCONTEXT hCard=(SCARDCONTEXT)NULL, hContext=(SCARDCONTEXT)NULL ;
    DWORD dwActiveProtocol=0,dwScope=0,dwState ;
	char Atr[ATRLEN];
	DWORD AtrLen;

    LONG stat;
	
	char *pname=Reader_String;
	DWORD dwReaders;
    int i=0,j=0,k=0,sboard=7;
          
	Reader_Nb=0    ;
    Reader_Nb_On= 0;

	for(i=0;i<MAX_READER;i++)
	{ Reader_Lock [i]   = -1  ;
      reader_no_seid(i)       ;
	}

    // ReadAllTables();
    
    dwScope= SCARD_SCOPE_SYSTEM;
	
	dwReaders = (int)sizeof(Reader_String);
    
 
    SCardListReadersA2((IN SCARDCONTEXT)NULL, (IN LPCSTR)NULL, Reader_String, &dwReaders);
		
	while(strlen(pname) != 0) 
	{   Reader_List[Reader_Nb]=pname;
		pname += (int)strlen(Reader_List[Reader_Nb]);
		pname++;	
		Reader_Nb++;
	}

sscanf(board,"%d",&sboard);

for(i=0;i<maxslots;i++)
{ Reader_Index_On[i]      = i                 ;
  Reader_Index_Abs[i]     = i+startslot       ;
  k= pushseid_d(100*sboard + i + startslot+1) ;
  SeidTable[k].num_reader  = i+startslot      ;
  
  if (secure_element_index ==1)
  {  k= pushseid_d(i)                            ;
     SeidTable[k].num_reader  = i+startslot      ;
  }

}

Reader_Nb_On= maxslots;
i = NBSC;

//Loop for PC/SC readers

while (i < Reader_Nb)
{      
        
		if (hCard != (SCARDCONTEXT)NULL)    stat = SCardDisconnect2(hCard,(DWORD)SCARD_LEAVE_CARD) ;
		if (hContext != (SCARDCONTEXT)NULL) stat = SCardReleaseContext2(hContext);

	    hContext=(SCARDCONTEXT)NULL ;
		hCard=(SCARDCONTEXT)NULL    ;

		stat = SCardEstablishContext2(dwScope, pvReserved1, pvReserved2, &hContext);
		
		if (stat  != SCARD_S_SUCCESS) continue ;

	    dwActiveProtocol=0;	

		stat = SCardConnectA2(hContext,(LPTSTR)Reader_List[i],
			//(DWORD)SCARD_SHARE_EXCLUSIVE, // BUG detected Sharing issue with weneo, SCARD_E_SHARING_VIOLATION  (0x8010000BL)
            (DWORD)SCARD_SHARE_SHARED,
			(DWORD)(SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1),
			 &hCard,
			 &dwActiveProtocol);
		i++;
		if (stat != SCARD_S_SUCCESS) continue;

		stat= SCardReconnect2(hCard,(DWORD)SCARD_SHARE_EXCLUSIVE,dwActiveProtocol,(DWORD)SCARD_UNPOWER_CARD,&dwActiveProtocol);
		
		if (stat != SCARD_S_SUCCESS) continue;

		AtrLen = sizeof(Atr);
		stat = SCardState2(hCard, &dwState, &dwActiveProtocol, Atr, &AtrLen);

		
		//=====================================================================
		//=====================================================================
		
		if ((stat != SCARD_S_SUCCESS) || (dwState == SCARD_ABSENT))  continue;

		Reader_Index_On[i-1]= Reader_Nb_On ;
		Reader_Index_Abs[Reader_Nb_On]= i-1;
        Reader_Nb_On++;

		if (secure_element_index ==1)
		{ //seid[j++]= i-1;
		  k= pushseid_d( Reader_Nb_On-1);
          SeidTable[k].num_reader =Reader_Index_Abs[Reader_Nb_On-1]  ;
		}
  
}

if (hCard != (SCARDCONTEXT)NULL)    
    stat = SCardDisconnect2(hCard,(DWORD)SCARD_UNPOWER_CARD) ;
if (hContext != (SCARDCONTEXT)NULL) 
    stat = SCardReleaseContext2(hContext);

//if (Reader_Nb_On ==0)              seid[999]= -1;
//else if (Reader_Nb_On == maxslots) seid[999]= Reader_Index_Abs[0];
//else                               seid[999]= Reader_Index_Abs[maxslots];

if (secure_element_index == 1)
{
 if (Reader_Nb_On == 0) ;
 else if (Reader_Nb_On == maxslots) 
 {	k= pushseid_d(999);
    SeidTable[k].num_reader = Reader_Index_Abs[0] ;
 }
 else
 {	k= pushseid_d(999);
    SeidTable[k].num_reader = Reader_Index_Abs[maxslots];
 }
}

return Reader_Nb_On;
}


#define PSIZE 16

int _TPDU(int num_reader,char *req, int sreq, char *resp, int*sresp, char *sw1, char *fetch, int sid);

int TPDU(int num_reader,char *req, int sreq, char *resp, int*sresp, char *sw1, char *fetch, int sid)
{ int err;

  MUTEX_LOCK(Pmutex[M_READER+num_reader]);
  err= _TPDU(num_reader,req,sreq,resp,sresp,sw1,fetch,sid);
  MUTEX_UNLOCK(Pmutex[M_READER+num_reader]);

  return err;
}

int _TPDU(int num_reader,char *req, int sreq, char *resp, int*sresp, char *sw1, char *fetch, int sid)
{ LONG stat;
  int more=1,more2=1;
  int ct=0,tot=0;
  char get[]= {(char)0x00,(char)0xC0, (char)0x00, (char)0x00, (char)0x00 };
  int i;
  
  DWORD size;

  struct timeb timebuffer1;
  struct timeb timebuffer2;
  long t1,t2,dtm ;

  int fmore=0    ;
  char SW1=0x61  ;

  SCARD_IO_REQUEST pioSendPci;

   if (Reader_Nb_On <=0) 
		 return -1 ;

   if (check_and_set_lock(num_reader,sid) != 0)
	  return -2;
 
   if (!iscard[num_reader]) 
		return -3;

  if      (dwActiveProtocol[num_reader] == SCARD_PROTOCOL_T0) 
  pioSendPci = *SCARD_PCI_T0;	 
  else if (dwActiveProtocol[num_reader] == SCARD_PROTOCOL_T1) 
  pioSendPci = *SCARD_PCI_T1;
  else 
  { iscard[num_reader]=0;return -1;}	



  if (sw1 != NULL)
  {  fmore=1;
     SW1=*sw1;
	 if (fetch != NULL)
	 { for (i=0;i<4;i++) get[i]=fetch[i]; }
  }

 

  
while(more2)
{

if (do_verbose)
{ gPrintf(indexs[num_reader],"Tx(%d): ",sid);
  for(i=0;i<sreq;i++)
  {	   if ( (i!=0) && (i%PSIZE == 0) ) gPrintf(indexs[num_reader],"\n         ");
       gPrintf(indexs[num_reader],"%2.2X ",(int) (0xFF & req[i]));
  }
  gPrintf(indexs[num_reader],"\n");
}

  size = (DWORD)*sresp;
  if (!iscard[num_reader]) return -1;

  ftime(&timebuffer1);

 
  /*
  if      (dwActiveProtocol[num_reader] == SCARD_PROTOCOL_T0) stat = SCardTransmit2(hCard[num_reader],SCARD_PCI_T0,req,sreq,NULL,&resp[ct],&size);
  else if (dwActiveProtocol[num_reader] == SCARD_PROTOCOL_T1) stat = SCardTransmit2(hCard[num_reader],SCARD_PCI_T1,req,sreq,NULL,&resp[ct],&size);
  else 
  { iscard[num_reader]=0;return -1;}	
  */

 stat = SCardTransmit2(hCard[num_reader], &pioSendPci,req,(DWORD)sreq,NULL,&resp[ct],&size);
   

ftime(&timebuffer2);
t1 =  (int)(0xFFFFFFFF & (timebuffer1.time % 3600)*1000 +   timebuffer1.millitm)   ;
t2 =  (int)(0xFFFFFFFF & (timebuffer2.time % 3600)*1000 +   timebuffer2.millitm)  ;

dtm = (t2-t1);
if (dtm <0) dtm += 3600000 ;

if (do_verbose)
{ gPrintf(indexs[num_reader],"Rx(%d): ",sid);       
  for(i=0;i<(int)size;i++)
  {	  if ( (i!=0) && (i%PSIZE == 0) ) gPrintf(indexs[num_reader],"\n         ");
      gPrintf(indexs[num_reader],"%2.2X ",(int)(0xFF &resp[i]));
  }
  gPrintf(indexs[num_reader],"(%d ms)\n", dtm);
}


  if (stat != SCARD_S_SUCCESS)  
  { iscard[num_reader]=0;
    return stat ;
  }

  //  6C xx
  if ( (sreq==5) && (size==2) && (resp[0]==(char)0x6C) &&  (resp[1]!=(char)0x00) )
  { req[4]=resp[1];}
  else  more2=0;

}


  
  while(more)
  {
  
  tot += size ;
  
  if ( fmore && (resp[ct+size-2] == (char)SW1) )
  {
	  
   get[4]= resp[ct+size-1] ;

   ct += (size-2)       ;
   tot-=2;
   size = (*sresp)-tot  ;
   
   if (size <= 258)
	   return -5;


if (do_verbose)
{ gPrintf(indexs[num_reader],"Tx(%d): ",sid);
  for(i=0;i<5;i++)
  {	   if ( (i!=0) && (i%PSIZE == 0) ) gPrintf(indexs[num_reader],"\n         ");
       gPrintf(indexs[num_reader],"%2.2X ",(int) (0xFF & get[i]));
  }
  gPrintf(indexs[num_reader],"\n");
}

ftime(&timebuffer1);

   /*
   if      (dwActiveProtocol[num_reader] == SCARD_PROTOCOL_T0) stat = SCardTransmit2(hCard[num_reader],SCARD_PCI_T0,get,5,NULL,&resp[ct], &size);
   else if (dwActiveProtocol[num_reader] == SCARD_PROTOCOL_T1) stat = SCardTransmit2(hCard[num_reader],SCARD_PCI_T1,get,5,NULL,&resp[ct], &size);
   else 
   { iscard[num_reader]=0;return -1;}
   */
   
   stat = SCardTransmit2(hCard[num_reader],&pioSendPci,get,(DWORD)5,NULL,&resp[ct], &size);

ftime(&timebuffer2);
t1 =  (int)(0xFFFFFFFF & (timebuffer1.time % 3600)*1000 +   timebuffer1.millitm)   ;
t2 =  (int)(0xFFFFFFFF & (timebuffer2.time % 3600)*1000 +   timebuffer2.millitm)  ;
dtm = (t2-t1);
if (dtm <0) dtm += 3600000 ;

   if (stat != SCARD_S_SUCCESS)  
   { iscard[num_reader]=0;
     return stat ;
   }

if (do_verbose)
{ gPrintf(indexs[num_reader],"Rx(%d): ",sid);       
  for(i=0;i<(int)size;i++)
  {	  if ( (i!=0) && (i%PSIZE == 0) ) gPrintf(indexs[num_reader],"\n         ");
      gPrintf(indexs[num_reader],"%2.2X ",(int)(0xFF & resp[ct+i]));
  }
  gPrintf(indexs[num_reader],"(%d ms)\n", dtm);
}


  }


  else   more=0;
  

  }

  
  *sresp = tot;
  return stat ;

}






int APDU(int num_reader,char *req, int sreq, char *resp, int*sresp)
{ LONG stat;
  int more=1,more2=1;
  int ct=0,tot=0;
  char get[]= {(char)0x00,(char)0xC0, (char)0x00, (char)0x00, (char)0x00 };
  int i;
  
  DWORD size;

  struct timeb timebuffer1;
  struct timeb timebuffer2;
  long t1,t2,dtm ;

  SCARD_IO_REQUEST pioSendPci;

  if      (dwActiveProtocol[num_reader] == SCARD_PROTOCOL_T0) 
  pioSendPci = *SCARD_PCI_T0;	 
  else if (dwActiveProtocol[num_reader] == SCARD_PROTOCOL_T1) 
  pioSendPci = *SCARD_PCI_T1;
  else 
  { iscard[num_reader]=0;return -1;}	


  
while(more2)
{

if (do_verbose)
{ gPrintf(indexs[num_reader],"Tx: ");
  for(i=0;i<sreq;i++)
  {	   if ( (i!=0) && (i%PSIZE == 0) ) gPrintf(indexs[num_reader],"\n    ");
       gPrintf(indexs[num_reader],"%2.2X ",(int) (0xFF & req[i]));
  }
  gPrintf(indexs[num_reader],"\n");
}

  size = (DWORD)*sresp;
  if (!iscard[num_reader]) return -1;

  ftime(&timebuffer1);


  /*
  if      (dwActiveProtocol[num_reader] == SCARD_PROTOCOL_T0) stat = SCardTransmit2(hCard[num_reader],SCARD_PCI_T0,req,sreq,NULL,&resp[ct],&size);
  else if (dwActiveProtocol[num_reader] == SCARD_PROTOCOL_T1) stat = SCardTransmit2(hCard[num_reader],SCARD_PCI_T1,req,sreq,NULL,&resp[ct],&size);
  else 
  { iscard[num_reader]=0;return -1;}
  */


stat = SCardTransmit2(hCard[num_reader],&pioSendPci,req,(DWORD)sreq,NULL,&resp[ct],&size);
 

ftime(&timebuffer2);
t1 =  (int)(0xFFFFFFFF & (timebuffer1.time % 3600)*1000 +   timebuffer1.millitm)   ;
t2 =  (int)(0xFFFFFFFF & (timebuffer2.time % 3600)*1000 +   timebuffer2.millitm)  ;

dtm = (t2-t1);
if (dtm <0) dtm += 3600000 ;

if (do_verbose)
{ gPrintf(indexs[num_reader],"Rx: ");       
  for(i=0;i<(int)size;i++)
  {	  if ( (i!=0) && (i%PSIZE == 0) ) gPrintf(indexs[num_reader],"\n    ");
      gPrintf(indexs[num_reader],"%2.2X ",(int)(0xFF &resp[i]));
  }
  gPrintf(indexs[num_reader],"(%d ms)\n", dtm);
}


  if (stat != SCARD_S_SUCCESS)  
  { iscard[num_reader]=0;
    return stat ;
  }

  //  6C xx
  if ( (sreq==5) && (size==2) && (resp[0]==(char)0x6C) &&  (resp[1]!=(char)0x00) )
  {  
	  req[4]=resp[1];
      
  }
  else
	  more2=0;

}


  
  while(more)
  {
  
  tot += size ;
  
  if ( resp[ct+size-2] == (char)0x61 )
  {
	  
   get[4]= resp[ct+size-1] ;

   ct += (size-2)       ;
   tot-=2;
   size = (*sresp)-tot  ;


if (do_verbose)
{ gPrintf(indexs[num_reader],"Tx: ");
  for(i=0;i<5;i++)
  {	   if ( (i!=0) && (i%PSIZE == 0) ) gPrintf(indexs[num_reader],"\n    ");
       gPrintf(indexs[num_reader],"%2.2X ",(int) (0xFF & get[i]));
  }
  gPrintf(indexs[num_reader],"\n");
}

ftime(&timebuffer1);

   /*
   if      (dwActiveProtocol[num_reader] == SCARD_PROTOCOL_T0) stat = SCardTransmit2(hCard[num_reader],SCARD_PCI_T0,get,5,NULL,&resp[ct], &size);
   else if (dwActiveProtocol[num_reader] == SCARD_PROTOCOL_T1) stat = SCardTransmit2(hCard[num_reader],SCARD_PCI_T1,get,5,NULL,&resp[ct], &size);
   else 
   { iscard[num_reader]=0;return -1;}
   */
   
   
   stat = SCardTransmit2(hCard[num_reader],&pioSendPci,get,(DWORD)5,NULL,&resp[ct], &size);


ftime(&timebuffer2);
t1 =  (int)(0xFFFFFFFF & (timebuffer1.time % 3600)*1000 +   timebuffer1.millitm)   ;
t2 =  (int)(0xFFFFFFFF & (timebuffer2.time % 3600)*1000 +   timebuffer2.millitm)  ;
dtm = (t2-t1);
if (dtm <0) dtm += 3600000 ;

   if (stat != SCARD_S_SUCCESS)  
   { iscard[num_reader]=0;
     return stat ;
   }

if (do_verbose)
{ gPrintf(indexs[num_reader],"Rx: ");       
  for(i=0;i<(int)size;i++)
  {	  if ( (i!=0) && (i%PSIZE == 0) ) gPrintf(indexs[num_reader],"\n    ");
      gPrintf(indexs[num_reader],"%2.2X ",(int)(0xFF & resp[ct+i]));
  }
  gPrintf(indexs[num_reader],"(%d ms)\n", dtm);
}


  }


  else more=0;

  }

  
  *sresp = tot;
  return stat ;

	
}







int quit(int num_reader)
{
	 SanityCheck(&hContext[num_reader],&hCard[num_reader]);
	 iscard[num_reader]=0 ;
     return(0) ;

}

int SanityCheck(SCARDCONTEXT *hContext,SCARDCONTEXT *hCard) {
	
	LONG stat;

	if (hCard != (SCARDCONTEXT)NULL)
		stat = SCardDisconnect2(*hCard,(DWORD)SCARD_UNPOWER_CARD) ;
	if (hContext != (SCARDCONTEXT)NULL)
		stat = SCardReleaseContext2(*hContext);

	*hContext=(SCARDCONTEXT)NULL ;
	*hCard   =(SCARDCONTEXT)NULL ;
	return 0;
}

int GetListAttrib(int num_reader) 
{ 
	ULONG Value;
	DWORD AttrLen;
	LONG stat;
	ULONG Tag;
	char IFD[][5] = {"T=..","CLK.","F...","D...","N...","W...","IFSC","IFSD","BWT.","CWT.","EBC.","EBWT"};

	for(Tag=0x201; Tag<=0x20C; Tag++) { 
		AttrLen = sizeof(Value);
		stat=SCardGetAttrib2(hCard[num_reader],SCARD_ATTR_VALUE(SCARD_CLASS_IFD_PROTOCOL,Tag),(LPBYTE)&Value,&AttrLen);
		if (stat == SCARD_S_SUCCESS && (AttrLen==4))
			gPrintf(indexs[num_reader],"%s Tag=%4.4X  Value= %8.8X  %d\n",IFD[Tag-0x201],Tag,Value,Value);
	}
	return(0);
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

		v &= 0xFF;data_out[j++]= v ;
		deb=fin=-1;iCt=0;
	   }
    }

return(j);
}