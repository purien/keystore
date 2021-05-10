/////////////////////////////////////////////////////////////////////////////
// atr.c ////////////////////////////////////////////////////////////////////
// Adapted from https://github.com/OpenSC/openct/blob/master/src/ifd/atr.c //
/////////////////////////////////////////////////////////////////////////////

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

int ifd_atr_parse(ifd_atr_info_t * info, unsigned char *atr, unsigned int len)
{
	unsigned int m, n, k=0,i,lenh=0;
	int fTCK=0;

	/* Initialize the atr_info struct */
	memset(info, 0, sizeof(*info));
	info->default_protocol = -1;
	for (n = 0; n < 3; n++) {
		info->TA[n] = -1;
		info->TB[n] = -1;
		info->TC[n] = -1;
	}

	if (len < (unsigned int)(2 + ((atr[1] & 0x0f)) ))
		return -1; // ERROR_INVALID_ATR;

	/* Ignore hystorical bytes */
	lenh = atr[1] & 0x0f;
	len -= lenh;

	for (m = 0, n = 2; n < len; m++) {
		unsigned int TDi;

		/* TA1, TA2, TA3, TA4 are legal, TA5 wouldn't be */
		if (m > 3)
			return -2 ; //ERROR_INVALID_ATR;

		TDi = atr[n - 1];
		if (n != 2) {
			int prot;

			prot = TDi & 0x0f;
			if (info->default_protocol < 0)
				info->default_protocol = prot;
			info->supported_protocols |= (1 << prot);
		}


		//k = ifd_count_bits(TDi & 0xF0);

		k=0;
        if (TDi & 0x10) k++;
		if (TDi & 0x20) k++;
        if (TDi & 0x40) k++;
		if (TDi & 0x80) k++;;

        if (k == 0 || n + k > len) 
			return -3; //ERROR_INVALID_ATR;
		

		if (TDi & 0x10)
			info->TA[m] = atr[n++];
		if (TDi & 0x20)
			info->TB[m] = atr[n++];
		if (TDi & 0x40)
			info->TC[m] = atr[n++];
		if (!(TDi & 0x80)) {
			/* If the ATR indicates we support anything
			 * in addition to T=0, there'll be a TCK byte
			 * at the end of the string.
			 * For now, simply chop it off. Later we may
			 * want to verify it.
			 */
			if (info->supported_protocols & ~0x1)
			{ fTCK=1; len--;}
			if (n < len)
				return -4; // ERROR_INVALID_ATR;
			break;
		}
		n++;
	}

	/* ATR didn't list any supported protocols, so
	 * we default to T=0 */
	if (info->supported_protocols == 0) {
		info->supported_protocols = 0x01;
		info->default_protocol = 1; //PROTOCOL_T0;
	}

	if (fTCK)
	{ k=0;
      for(i=1;i<(len+lenh);i++)
		  k= k ^ atr[i];

	  if (k != (unsigned int)atr[len+lenh])
		  return -10; // TCK ERROR
    }
	
	return fTCK;
}