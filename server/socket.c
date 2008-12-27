/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: socket.c,v 1.12.2.1 2008/09/02 08:26:17 dembour Exp $
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
#include <stdlib.h>
#ifndef _WIN32
#include <sys/socket.h>     
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#endif

#include "dns.h"
#include "server.h"
#include "myerror.h"
#include "debug.h"

int			bind_socket(t_conf *conf)
{
  int			ret;
  struct sockaddr_storage ss;
  struct addrinfo	*res, hints;
  socklen_t		slen;

  memset(&ss, 0, sizeof(ss));

  slen = sizeof(struct sockaddr_in);
  if (conf->my_ip)
    {
      DPRINTF(1, "Listenning on %s:%d for domain %s\n", conf->my_ip, 
	      conf->port, conf->my_domain);
      memset(&hints, 0, sizeof(hints));
      hints.ai_flags    = AI_CANONNAME;
      hints.ai_family   = PF_UNSPEC;
      hints.ai_socktype = SOCK_DGRAM;
      res = NULL;
      if ((ret = getaddrinfo(conf->my_ip, NULL, &hints, &res)) || !res)
        {
          MYERROR("getaddrinfo: %s\n", gai_strerror(ret));
          return (-1);
        }
      switch (res->ai_family) {
        case AF_INET:
          memcpy(&((struct sockaddr_in *) &ss)->sin_addr.s_addr,
		 &((struct sockaddr_in *) res->ai_addr)->sin_addr,
		 sizeof(struct in_addr));
          ((struct sockaddr_in *) &ss)->sin_port = htons(conf->port);
	  break;
	case AF_INET6:
	  memcpy(&((struct sockaddr_in6 *) &ss)->sin6_addr,
	         &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr,
		 sizeof(struct in6_addr));
          ((struct sockaddr_in6 *) &ss)->sin6_port = htons(conf->port);
          slen = sizeof(struct sockaddr_in6);
	  break;
	default:
          freeaddrinfo(res);
	  return (-1);
      }
      ss.ss_family = res->ai_family;
      freeaddrinfo(res);
    }
  else
    {
      ss.ss_family = AF_INET;
      ((struct sockaddr_in *) &ss)->sin_addr.s_addr = INADDR_ANY;
      ((struct sockaddr_in *) &ss)->sin_port = htons(conf->port);
      DPRINTF(1, "Listenning on 0.0.0.0:%d for domain %s\n", conf->port, 
	      conf->my_domain);
    }
  if ((conf->sd_udp = socket(ss.ss_family, SOCK_DGRAM, 0)) < 0)
    {
      MYERROR("socket error");
      return (-1);
    }
  if (bind(conf->sd_udp, (struct sockaddr *) &ss, slen) < 0)
    {
      close(conf->sd_udp);
      MYERROR("bind error");
      return (-1);
    }
  return (0);      
}

int			connect_socket(char *name, uint16_t port, int *sd)
{
  int ret;
  char *host, *end;
  struct sockaddr_storage ss;
  struct addrinfo *res, *ptr, hints;

  /* strip [] from "[ip]" */
  if (*name == '[')
    {
      end = strchr(name+1, ']');
      if (!end || end[1] || (end == name+1))
        {
          MYERROR("invalid ressource's name (missing ']')\n");
	  return (-1);
        }
      if (!(host = strdup(name+1)))
        {
	  MYERROR("cannot duplicate hostname\n");
	  return (-1);
        }
      host[end-name-1] = 0;
    }
  else
    {
      host = name;
    }

  memset(&hints, 0, sizeof(hints));
  hints.ai_flags    = AI_CANONNAME;
  hints.ai_family   = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  res = NULL;
  ret = getaddrinfo(host, NULL, &hints, &res);
  if (host != name)
    free(host);
  if (ret || !res)
    {
      MYERROR("getaddrinfo: %s (%s)\n", gai_strerror(ret), host);
      return (-1);
    }

  for (ptr=res; ptr; ptr=ptr->ai_next)
    {
      memset(&ss, 0, sizeof(ss));
      switch (ptr->ai_family) {
        case AF_INET:
	  ((struct sockaddr_in *) ptr->ai_addr)->sin_port = htons(port);
	  break;
	case AF_INET6:
	  ((struct sockaddr_in6 *) ptr->ai_addr)->sin6_port = htons(port);
	  break;
	default:
	  return (-1);
      }

      ss.ss_family = ptr->ai_family;
      if ((*sd = socket(ptr->ai_family, SOCK_STREAM, 0)) < 0)
        {
	  MYERROR("socket error");
	  break;
	}
      DPRINTF(1, "Connecting to %s port %d\n", name, port);
      if (!connect(*sd, ptr->ai_addr, ptr->ai_addrlen)) {
	freeaddrinfo(res);
        return (0);
      }

      MYERROR("connect error");
      close(*sd);
    }
  freeaddrinfo(res);
  return (-1);
}

