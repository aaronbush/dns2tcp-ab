/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: packet.h,v 1.6 2007/01/29 17:47:44 dembour Exp $
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

#ifndef __PACKET_H__
#define __PACKET_H__

#ifndef _WIN32
#include <netdb.h>
#include <netinet/in.h>
#include <sys/time.h>
#else
#include "mywin32.h"
#endif

#include "list.h"
#include "memdump.h"

/* type */

#define OK		0x0
#define DESAUTH		0x1
#define ERR		0x2
#define AUTH		0x3
#define	NOP		0x4

#define DATA		(1 << 3)
#define ACK		(1 << 4)
#define NACK		(1 << 5)
#define USE_COMPRESS	(1 << 6)

/* end type */

/*
Error MSG
*/
#define MAX_ERROR_SIZE	64

#define ERR_RESSOURCE		"Ressource Unknown"
#define ERR_CONN_REFUSED	"Connexion refused"
#define ERR_BAD_SEQ		"Bad seq number"

#undef MIN
#define MIN(a,b)	((a) > (b) ? (b) : (a))

/* Avoid padding error */
#define	PACKET_LEN	7

#define MAX_SEQ 0xffff

typedef struct		s_packet {
  uint16_t		cookie;
  uint16_t		ack_seq;
  uint16_t		seq;
  uint8_t		type;
}			t_packet;
/* DATA goes  after */

#endif
