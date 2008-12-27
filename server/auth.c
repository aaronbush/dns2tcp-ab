/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: auth.c,v 1.14 2007/05/29 13:58:41 dembour Exp $
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

#include <time.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <time.h>

#include "server.h"
#include "dns.h"
#include "list.h"
#include "requests.h"
#include "base64.h"
#include "myrand.h"
#include "socket.h"
#include "server_queue.h"
#include "debug.h"
#include "log.h"


static int		build_login_reply(void *req, uint16_t cookie, int max_len)
{

  struct dns_hdr	*hdr;
  void			*where;
  t_packet		packet;
  char			buffer[2*PACKET_LEN];

  hdr = req;
  hdr->ra = 1;
  hdr->qr = 1;
  if (!(where = jump_end_query(req, GET_16(&hdr->qdcount), max_len)))
    return (-1);
  packet.cookie = cookie;
  packet.ack_seq = 0;
  packet.seq = 0;
  packet.type = OK|AUTH ;
  base64_encode((char *)&packet, buffer, PACKET_LEN);
  where = add_reply(hdr, where, TYPE_KEY, buffer);
  return (where - req);
}

static int		connect_ressource(t_conf *conf, char *ressource, void *req, int in_len, int *sd)
{
  t_list		*list_ressource;
  int			len;
  
  len = strlen(ressource);
  for (list_ressource = conf->ressources; list_ressource; list_ressource = list_ressource->next)
    {
      if ((!strncmp(list_ressource->data, ressource, len)) 
	  && (list_ressource->data[len] == ':'))
      {
	  if (connect_socket(strchr(list_ressource->data, ':') + 1, list_ressource->info.port, sd))
	    return (build_error_reply(conf, req, in_len, ERR_CONN_REFUSED));
	  return (0);
	}
    }
  return (build_error_reply(conf, req, in_len, ERR_RESSOURCE));
}

static uint16_t		create_env(t_conf *conf, void *req, void *data, int in_len, struct sockaddr_in *sa)
{
  t_simple_list		*client;
  int			sd;
  t_packet		*packet;
  char			*ressource;
  int			len;
  time_t		mytime;

  packet = data;
  ressource = data + PACKET_LEN;
  if ((len = connect_ressource(conf, ressource, req, in_len, &sd)))
    return (len);
  client = (t_simple_list *)conf->client;
  if (!client)
    {
      conf->client = list_create_simple_cell();
      client = conf->client;
    }
  else
    {
      while (client->next)
	client = client->next;
      if (!(client->next = list_create_simple_cell()))
	return (-1);
      client = client->next;
    }
  client->cookie = myrand();
  client->sd_tcp = sd;
  client->queue = init_queue();
  client->num_seq = 1;
  queue_update_timer(client);
  if ((packet->type & USE_COMPRESS) == USE_COMPRESS)
    client->control.use_compress = 1;
  time(&mytime);
#ifndef WORDS_BIGENDIAN
  LOG("add client id: 0x%x address = %u.%u.%u.%u ressource %s", client->cookie,
      (unsigned int) ((sa->sin_addr.s_addr) & 0xff),
      (unsigned int) ((sa->sin_addr.s_addr >> 8) & 0xff),
      (unsigned int) ((sa->sin_addr.s_addr >> 16) & 0xff),
      (unsigned int) ((sa->sin_addr.s_addr >> 24) & 0xff), ressource);
#else
  LOG("add client id: 0x%x address = %u.%u.%u.%u ressource %s", client->cookie,
      (unsigned int) ((sa->sin_addr.s_addr >> 24) & 0xff),
      (unsigned int) ((sa->sin_addr.s_addr >> 16) & 0xff),
      (unsigned int) ((sa->sin_addr.s_addr >> 8) & 0xff),
      (unsigned int) ((sa->sin_addr.s_addr) & 0xff), ressource);
#endif
  return (build_login_reply(req, client->cookie, in_len));	  
}

int		login_user(t_conf *conf, void *req, char *buffer, int in_len, struct sockaddr_in *sa)
{
  t_packet	*packet;

  packet = (void *)buffer;
  if ((packet->type & AUTH) == AUTH) 
    return (create_env(conf, req,  buffer, in_len, sa));
      
  /*
    Verif nom de connection 
    + chap
   */
  return (0);
}

