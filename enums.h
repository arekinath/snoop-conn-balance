#if !defined(_ENUMS_H)
#define _ENUMS_H

enum ipproto {
	PR_TCP = 0x06,
	PR_UDP = 0x11
};

enum tcpflag {
	TCPFL_FIN = (1<<0),
	TCPFL_SYN = (1<<1),
	TCPFL_RST = (1<<2),
	TCPFL_PSH = (1<<3),
	TCPFL_ACK = (1<<4)
};

enum mactypes {
	MAC_IP4 = 0x0800,
	MAC_ARP = 0x0806,
	MAC_DOT1Q = 0x8100,
	MAC_IP6 = 0x86DD
};

enum nsmeta {
	NSM_STRING = 0x00,
	NSM_PTR = 0xc0,
	NSM_MASK = 0xc0
};

enum nsclass {
	NSC_IN = 0x01,
	NSC_CS = 0x02,
	NSC_CH = 0x03,
	NSC_HS = 0x04
};

enum nstype {
	NST_A = 0x01,
	NST_NS = 0x02,
	NST_CNAME = 0x05,
	NST_AAAA = 0x1c,
	NST_SRV = 0x21
};

enum nspos {
	NSP_QUESTION = 0,
	NSP_ANSWER = 1,
	NSP_AUTHORITY = 2,
	NSP_ADDITIONAL = 3
};

#endif
