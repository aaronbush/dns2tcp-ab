/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: socket.c,v 1.9 2007/05/29 13:58:41 dembour Exp $
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
#include <string.h>
#include <fcntl.h>
#ifndef _WIN32
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <termios.h>
#else
#include "mywin32.h"
#endif

#include "client.h"
#include "dns.h"
#include "myerror.h"
#include "debug.h"


int			get_simple_reply(t_conf *conf, void *buffer, uint16_t id)
{
  fd_set                rfds;
  struct timeval        tv;
  int                   retval;
  struct dns_hdr	*hdr;
  int			len = 0; 

  FD_ZERO(&rfds);
  FD_SET(conf->sd_udp, &rfds);
  tv.tv_sec = 3;
  tv.tv_usec = 0;
  hdr = buffer;

  while ((retval = select(conf->sd_udp+1, &rfds, NULL, NULL, &tv)) != -1)
    {
      if (!retval)
	{
	  fprintf(stderr, "No response from DNS %s\n", conf->dns_server);
	  return (-1);
	}
      if (FD_ISSET(conf->sd_udp, &rfds))
	{
	  len = read(conf->sd_udp, buffer, MAX_REQ_LEN);
	  if (hdr->id == id)
	    return (len);
	}
      FD_SET(conf->sd_udp, &rfds);
      tv.tv_sec = 3;
    }
  MYERROR("Select error");
  return (-1);
}

static int	set_nonblock(socket_t sd)
{
#ifndef _WIN32
  int		opt;

  if ((opt = fcntl(sd, F_GETFL)) == -1)
    return (-1);
  if ((opt = fcntl(sd, F_SETFL, opt|O_NONBLOCK)) == -1)
    return (-1);
#endif
  return (0);
}

int			bind_socket(t_conf *conf)
{
  struct sockaddr_in	sa;
  int			optval = 1;
  
  memset(&sa,0,sizeof(struct sockaddr_in));
  sa.sin_port = htons(conf->local_port);
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_family = AF_INET;
  if ((conf->sd_tcp = socket(PF_INET, SOCK_STREAM, 0)) < 0)
    {
      MYERROR("socket error %hd", conf->local_port);
      return (-1);
    }
  if (!setsockopt(conf->sd_tcp, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)))
    {
      if (bind(conf->sd_tcp, (struct sockaddr *) &sa, sizeof(struct sockaddr_in)) < 0)
	{
	  perror("bind error");
	  return (-1);
	}
      if ((!set_nonblock(conf->sd_tcp))
	  && (!listen(conf->sd_tcp, 10)))
	{
	  fprintf(stderr, "Listenning on port : %d\n", conf->local_port);
	  return (0);
	}
    }
  MYERROR("Socket_error");
  return (-1);      
}

socket_t		create_socket(t_conf *conf, struct sockaddr_in *sa)
{
  struct hostent        *hostent;
  socket_t		sd;

  if (!(hostent = gethostbyname(conf->dns_server)))
    {
      MYERROR("Gethostbyname \'%s\'",conf->dns_server);
      return (-1);
    }
  sa->sin_port = htons(53);
  memcpy(&sa->sin_addr.s_addr, hostent->h_addr, sizeof(sa->sin_addr.s_addr));
  sa->sin_family = AF_INET;
  if ((sd = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
    {
      MYERROR("socket error");
      return (-1);
    }
  DPRINTF(3, "Create socket for dns : \'%s\' \n", conf->dns_server);
  return (sd);      
}


