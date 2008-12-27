/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: main.c,v 1.6 2007/05/30 13:04:45 dembour Exp $
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
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>

#ifndef _WIN32
#include <unistd.h>
#include <sys/time.h>
#else
#include "mywin32.h"
#endif

#include "client.h"
#include "options.h"
#include "socket.h"
#include "auth.h"
#include "myerror.h"
#include "dns.h"


int			main(int argc, char **argv)
{
  t_conf		conf;
  struct sockaddr_in	sa;

  if ((get_option(argc, argv, &conf)) ||  
      ((conf.sd_udp = create_socket(&conf, &sa)) < 0))
      return (-1);
  srand(getpid() ^ (unsigned int) time(0));
  if (!conf.ressource)
    return (list_ressources(&conf, &sa));
  if (! bind_socket(&conf))
    do_client(&conf, &sa);
  return (0);
}
