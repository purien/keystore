/* windowsglue.c */
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


#ifndef WIN32
#define HWND int
#else
#include <windows.h>
#endif


int NC=140       ; // max character perline
int wBG= 0xFFFFFF; // Background
int wPEN= 0  ;     // Pen color
int wSIZE= 18;     // Fonte Size

int system_console=1   ; // use system console
int reader_console=1   ; // use console for reader
int is_external_grid=1 ; // use implemta grid
int autostart=1        ; // auto start
int startdelay=0       ; // delay for autostart ms


int startnewconsole(char *name);
int closeconsole(int index);
HWND gethWnd(int id);
int tile();

// Return an id for a console
// 0 system
// 1...nbReaderOn                   SmartCardReader
// 1+NbReaderOn..... 1+NbReaderOn + MAX_DISPLAY server
// return -1 if no resource is available
int startnewconsole(char *name)
{ // need a mutuex
	return 0;
}

// Close a console
int closeconsole(int index)
{
	return 0;
}

// Return a HWND associated to a console id

HWND gethWnd(int id)
{
	return 0;
}
int tile()
{
	return 0;
}


int setconsole_name(int id, char *name)
{  
#ifdef  WIN32
   SetConsoleTitle(name);
#endif

return 0;
}
