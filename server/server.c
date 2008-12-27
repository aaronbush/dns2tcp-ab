/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: server.c,v 1.13 2007/01/24 13:34:01 dembour Exp $
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

#include <stdio.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

#include "server.h"
#include "dns.h"
#include "list.h"
#include "myerror.h"
#include "requests.h"
#include "server_queue.h"
#include "queue.h"
#include "debug.h"
#include "log.h"



#define SOCKET_TIMEOUT	1 /* 1s */

static int      prepare_select(t_conf *conf, fd_set *rfds, struct timeval *tv)
{
  int           max_fd = 0;
  t_simple_list *client;

  FD_ZERO(rfds);
  client = conf->client;

  while (client)
    {
      if ((client->sd_tcp != -1) && (!(client->control.queue_full)))
        {
          FD_SET(client->sd_tcp, rfds);
          max_fd = MAX(max_fd, client->sd_tcp);
        }
      client = client->next;
    }
  FD_SET(conf->sd_udp, rfds);
  if (conf->foreground)
    FD_SET(0, rfds);
  max_fd = MAX(max_fd, conf->sd_udp);
  tv->tv_sec = SOCKET_TIMEOUT;
  tv->tv_usec = 0;
  return (max_fd);
}

int		delete_client(t_conf *conf, t_simple_list *client)
{
  t_simple_list	*tmp;

  if (conf->client == client)
    {
      tmp = client->next;
      LOG("delete_client 0x%x\n", client->cookie);
      list_destroy_simple_cell(conf->client);
      conf->client = tmp;
      return (0);
    }
  for (tmp = conf->client; tmp; tmp = tmp->next)
    {
      if (tmp->next == client)
	{
	  tmp->next = client->next;
	  LOG("delete_client 0x%x\n", client->cookie);
	  delete_queue(client->queue);
	  return (list_destroy_simple_cell(client));
	}
    }
  return (-1);
}


void			delete_zombie(t_conf *conf)
{
  t_simple_list		*client;
  t_simple_list		*tmp;
  struct timeval	tv;
  struct timezone	tz;
  
  if (!(gettimeofday(&tv, &tz)))
    for (client = conf->client; client; client = tmp)
      {
	tmp = client->next;
	if (tv.tv_sec > client->control.tv.tv_sec)
	  {
	    close(client->sd_tcp);
	    delete_client(conf, client);
	  }
      }
}

#define MINI_BUFF 64

int			do_server(t_conf *conf)
{
  fd_set		rfds;
  int			retval;
  int			max_fd;
  t_simple_list		*client;
  t_simple_list		*tmp;
  struct timeval	tv;
  struct timezone	tz;
  char		        buffer[MINI_BUFF];
  
  while (1)
    {     
      max_fd = prepare_select(conf, &rfds, &tv);
      retval = select(max_fd + 1 , &rfds, NULL, NULL, &tv);
      if (retval == -1)
	{
	  perror("");
	  MYERROR("select");
	  return (-1);
	}
      if (!retval)
	{ 
	  if (gettimeofday(&tv, &tz))
	    {
	      MYERROR("Time Error");
	      return (-1);
	    }
	  delete_zombie(conf);
	  continue;
	}
      if ((conf->foreground) && (FD_ISSET(0, &rfds)))
	{
	  read(0, buffer, MINI_BUFF); 
	  queue_dump(conf->client);
	  continue;
	}
      if (FD_ISSET(conf->sd_udp, &rfds))
	get_incoming_request(conf);
      else
	{
	  for (client = conf->client;  client; client = tmp)
	    {
	      tmp = client->next;
	      if (FD_ISSET(client->sd_tcp, &rfds))
	      {
		if (queue_read_tcp(conf, client))
		  {
		    close(client->sd_tcp);
		    delete_client(conf, client);
		  }
	      }
	    }
	}
      delete_zombie(conf);
    }
}

