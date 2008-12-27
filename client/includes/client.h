/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: client.h,v 1.7 2007/01/26 16:13:44 collignon Exp $
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

#ifndef __CLIENT_H__
#define __CLIENT_H__


/* 
   QUEUE_SIZE must the same that server value 
*/
#define QUEUE_SIZE	48

#define WINDOW_SIZE	(QUEUE_SIZE / 2)
#define	NOP_SIZE	(WINDOW_SIZE / 3)
#define	MAX_NOP_SIZE	(NOP_SIZE * 2)
#define	MAX_DATA_SIZE	(WINDOW_SIZE - NOP_SIZE)

#define SOCKET_TIMEOUT  1 /* 1s */
#define REPLY_TIMEOUT	1 /* 1s */


#include "packet.h"

typedef struct		s_conf {
  uint16_t		local_port;
  socket_t		sd_udp;
  socket_t		sd_tcp;
  uint16_t		id;
  char			*domain;
  char			*secret;
  char			*ressource;
  uint8_t		use_compression;
  char			*dns_server;
  struct s_simple_list	*client;
}			t_conf;

int delete_client(t_conf *conf, struct s_simple_list *client);
int do_client(t_conf *, struct sockaddr_in *);

#endif
