/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: dns.h,v 1.10 2007/05/29 16:46:50 dembour Exp $
**
** 
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with This program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef __DNS_H__
#define __DNS_H__

#include "config.h"

#ifndef _WIN32
#include <arpa/inet.h>
#else
#include "mywin32.h"
#endif
#include "base64.h"

#define MAX_REQ_LEN			512

#define MAX_HOST_NAME_ENCODED		200 
#define MAX_HOST_NAME_DECODED		DECODED_LEN((MAX_HOST_NAME_ENCODED))

#define ENCODED_LEN(len)		(((len) + (((len) / 63) + 1)))
#define DECODED_LEN(len)		(((len) - (((len) / 63) + 1)))

#define MAX_TXT_DATA(len)	\
	(DECODED_LEN(DECODE_BASE64_SIZE(\
			(MAX_REQ_LEN - (\
				(len) + \
				RR_HDR_SIZE + sizeof(uint16_t) + 1 )\
		))))

#define AUTHORITATIVE_SIZE 0x40 /* should be better define ... */
/* Additional record + Authoritative nameserver */


#define TXT_DATA_AVAILABLE(len, query_len)  (client->control.use_compress) ? \
				((MAX_TXT_DATA((len) + (AUTHORITATIVE_SIZE)))) : \
				((MAX_TXT_DATA((len) + (query_len) + (AUTHORITATIVE_SIZE))))

#define	MAX_QNAME_DATA(domain)		(DECODE_BASE64_SIZE(MAX_HOST_NAME_DECODED - strlen(domain) - 1))

/* GCC alignement padding workaround */

#define DNS_HDR_SIZE			12
#define	RR_HDR_SIZE			10
#define	REQ_HDR_SIZE			4

#define	JUMP_DNS_HDR(hdr)		((char *)hdr + DNS_HDR_SIZE)
#define	JUMP_RR_HDR(hdr)		((char *)hdr + RR_HDR_SIZE)
#define	JUMP_REQ_HDR(hdr)		((char *)hdr + REQ_HDR_SIZE)

#define COMPRESS_FLAG_CHAR		0xC0
#define COMPRESS_FLAG			0xC000
#define	GET_DECOMPRESS_OFFSET(offset)	((ntohs(offset)) & ~(COMPRESS_FLAG))

/* Just like that */
#define	MAX_COMPRESS_DEPTH		10


/* Network order */
#define PUT_16(dst, src) do \
	{\
		((unsigned char *)(dst))[0] = ((src) & 0xff00) >> 8; \
		((unsigned char *)(dst))[1] = ((src) & 0xff); \
	} while (0)

/* Host order */
#define GET_16(src) ((((unsigned char *)(src))[0] << 8) | (((unsigned char *)(src))[1]) )


struct				dns_hdr {
  uint16_t			id;
#ifndef WORDS_BIGENDIAN
  uint16_t			rd:1, /* recurse demand */
				tc:1,
				aa:1,
				opcode:4,
				qr:1,
				rcode:4,
				z:3,
				ra:1; /* recurse available */
#else
  uint16_t			qr:1,
				opcode:4,
				aa:1,
				tc:1,
				rd:1,
				ra:1,
				z:3,
				rcode:4;
#endif
#define RCODE_NO_ERR		0x0
#define RCODE_FORMAT_ERR	0x1
#define RCODE_SRV_FAILURE	0x2
#define RCODE_NAME_ERR		0x3
#define RCODE_NOT_IMPLEMENTED	0x4
#define RCODE_REFUSED		0x3
  uint16_t			qdcount; /* quries number */
  uint16_t			ancount;
  uint16_t			nscount;
  uint16_t			arcount;
};


#define MAX_DNS_ERROR	6
extern const char *dns_error[MAX_DNS_ERROR];

struct		req_hdr {
  uint16_t	qtype; /* TXT */
  uint16_t	qclass; /* IN | CHAOS */
};

struct		rr_hdr {
  uint16_t	type;
#define TYPE_TXT 16
#define TYPE_KEY 25
  uint16_t	klass;
#define CLASS_IN 1
  uint32_t	ttl;
  uint16_t	rdlength;
};

void    dns_simple_decode(char *input, char *output, int max_len);
void	dns_encode(char *);
void	*jump_end_query(void *, int, int);
#ifndef _WIN32
int	strnlen(char *, int len);
#endif

#endif
