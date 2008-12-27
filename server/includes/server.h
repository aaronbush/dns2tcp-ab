/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: server.h,v 1.8 2007/01/24 13:34:02 dembour Exp $
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

#ifndef __SERVER_H__
#define __SERVER_H__

#include "packet.h"

#define CLIENT_TIMEOUT	8 /* seconds */

/* when we have more than FLUSH_TRIGGER  queries in queue, we try to flush */
#define FLUSH_TRIGGER	(QUEUE_SIZE /4)

/* 
   QUEUE_SIZE must the same that server value 
*/
#define QUEUE_SIZE      48


typedef struct		s_conf {
  struct s_list		*ressources;
  struct s_simple_list	*client;
  int			sd_udp;
  char			*my_domain;
  char			*chroot;
  char			*user;
  char			*my_ip;
  uint16_t		port;
  uint8_t		list_ressource;
  uint8_t		foreground;
}			t_conf;

int	do_server(t_conf *);
int	strnlen(char *, int); /* not present ?*/
int	delete_client(t_conf *conf, struct s_simple_list *client);
void	delete_zombie(t_conf *conf);

#endif
