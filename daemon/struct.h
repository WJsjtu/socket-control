typedef struct _CC_Site {
	char IP[16];
	int port;
} _CC_Site;

typedef struct _CC_Config{
	int TCP;
	int UDP;
	int length;
	int port;
	_CC_Site arr[256];
} _CC_Config;