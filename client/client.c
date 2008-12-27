/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: client.c,v 1.11 2007/05/22 10:15:13 dembour Exp $
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
#include <time.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#include <sys/select.h>
#else
#include "mywin32.h"
#endif


#include "dns.h"
#include "list.h"
#include "myerror.h"
#include "client.h"
#include "queue.h"
#include "auth.h"
#include "debug.h"


static int	prepare_select(t_conf *conf,fd_set *rfds, struct timeval *tv)
{
  socket_t	max_fd = 0;
  t_simple_list	*client;

  FD_ZERO(rfds);
  client = conf->client;

  while (client) 
    {
      if (client->sd_tcp != -1)
	{
	  queue_put_nop(conf, client);
	  if (!(client->control.data_pending >= MAX_DATA_SIZE)
	      && (!(client->control.data_pending + client->control.nop_pending >= WINDOW_SIZE)))
	    {
	      FD_SET(client->sd_tcp, rfds);
	      max_fd = MAX(max_fd, client->sd_tcp);
	    }
	}
      client = client->next;
    }
  FD_SET(conf->sd_udp, rfds);
  FD_SET(0, rfds);
  FD_SET(conf->sd_tcp, rfds);
  max_fd = MAX(max_fd, conf->sd_udp);
  max_fd = MAX(max_fd, conf->sd_tcp);
  tv->tv_sec = SOCKET_TIMEOUT;
  tv->tv_usec = 0;
  return (int) (max_fd);
}

int		delete_client(t_conf *conf, t_simple_list *client)
{
  t_simple_list	*tmp;

  DPRINTF(1, "free client \n");
  if (conf->client == client)
    {
      close(client->sd_tcp);
      tmp = client->next;
      delete_queue(client->queue);
      list_destroy_simple_cell(conf->client);
      conf->client = tmp;
      return (0);
    }
  for (tmp = conf->client; tmp; tmp = tmp->next)
    {
      if (tmp->next == client)
	{
	  tmp->next = client->next;
	  delete_queue(client->queue);
	  return (list_destroy_simple_cell(client));
	}
    }
  return (-1);
}

int		add_client(t_conf *conf, socket_t sd, struct sockaddr_in *sa)
{
  uint16_t	cookie;
  t_simple_list	*client;
  
  if (!(cookie = connect_ressource(conf, sa)))
      return (-1);
  DPRINTF(1, "Adding client auth OK: 0x%hx\n", cookie);
  if (!(conf->client))
    {
      if (!(conf->client = list_create_simple_cell()))
	return (-1);
      client = conf->client;
    }
  else
    {
      client = conf->client;
      while (client->next)
	client = client->next;
      if (!(client->next = list_create_simple_cell()))
	return (-1);
      client = client->next;
    }
  client->cookie = cookie;
  client->sd_tcp = sd;
  client->control.data_pending = 0;
  client->control.nop_pending = 0;
  client->num_seq = 0;
  memcpy(&(client->control.peer), sa, sizeof(struct sockaddr_in));
  if (! (client->queue = init_queue()))
    return (-1);
  return (0);
}

#define MINI_BUFF 64

int		get_socket_data(t_conf *conf, fd_set *rfds, struct sockaddr_in *sa)
{
  socket_t	sd;
  t_simple_list	*client;
  char		buffer[MINI_BUFF];
  
  if (FD_ISSET(0, rfds))
    {
      read(0, buffer, MINI_BUFF);
      if ((client = conf->client))
	{
	  for (; client; client = client->next)
	    queue_dump(client);
	}
      else
	DPRINTF(2, "No more client\n");
      return (0);
    }
  client = conf->client;
  if (FD_ISSET(conf->sd_udp, rfds))
    {
      if (!client)
	read(conf->sd_udp, buffer, MINI_BUFF);
      if ((client) && (queue_get_udp_data(conf, client)))
	{
	  MYERROR("getting data\n"); 
	  return (-1);
	}
      return (0);
    }
  for (client = conf->client; client; client = client->next)
    {      
      if (client->sd_tcp != -1)
	if (FD_ISSET(client->sd_tcp, rfds))
	  {
	    if (queue_get_tcp_data(conf, client))
		return (delete_client(conf, client));
	    return (0);
	  }
    }
  if (FD_ISSET(conf->sd_tcp, rfds))
    {
      if ((sd = accept(conf->sd_tcp, 0, 0)) == -1)
	{
	  MYERROR("accept");
	  return (-1);
	}
      if (add_client(conf, sd, sa))
	close(sd);
      return (0);
    }
  return (-1);
}

int			do_client(t_conf *conf, struct sockaddr_in *sa)
{
  fd_set                rfds;
  struct timeval        tv;
  int                   retval;
  int                   max_fd;

  if (debug >= 2)
    fprintf(stderr, "When connected press enter at any time to dump the queue\n");
  while (1)
    {
      max_fd = prepare_select(conf, &rfds, &tv);
      if ((retval = select(max_fd+1, &rfds, 0, 0, &tv)) == -1)
	{
	  MYERROR("select error");
		return (-1);
	}
      if (retval)
	{
	  if (get_socket_data(conf, &rfds, sa))
	    {
	      MYERROR("Error in select");
	      return (-1);
	    }
	}
      check_for_resent(conf);
    }
  return (-1);
}
