/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: control.h,v 1.5 2007/05/22 14:50:28 dembour Exp $
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

#ifndef __CONTROL_H__
#define __CONTROL_H__

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#else
#include <winsock2.h>
#endif

#define MAX_CLIENT_ERROR	10

typedef	struct		s_control {
  uint16_t		nop_pending;
  uint16_t		data_pending;
  uint8_t		cumul_errors;
  struct sockaddr_in	peer;
}			t_control;

typedef struct		s_control_peer {
  uint16_t		ack_seq;
  uint16_t		id;
  uint8_t		type;
}			t_control_peer;


#endif
