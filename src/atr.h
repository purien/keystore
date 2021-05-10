typedef struct ifd_atr_info {
		/* The following contain -1 if the field wasn't present */
		int TA[4];
		int TB[4];
		int TC[4];
		unsigned int supported_protocols;
		int default_protocol;
	} ifd_atr_info_t;


extern int ifd_atr_parse(ifd_atr_info_t * info, unsigned char *atr, unsigned int len);
