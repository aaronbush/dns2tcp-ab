/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: options.c,v 1.10 2007/05/29 14:51:14 dembour Exp $
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
#include <unistd.h>       
#include <strings.h>
#include <string.h>
#include <stdlib.h>

#include "server.h"
#include "dns.h"
#include "list.h"
#include "my_config.h"
#include "debug.h"
#include "log.h"




static void	usage(char *name)
{
  fprintf(stderr, "Usage :%s [ -i IP ] [ -F ] [ -d debug_level ] [ -f config-file ]\n", name);
  fprintf(stderr, "\t -F : dns2tcpd will run in foreground\n");
}

static int	check_mandatory_param(t_conf *conf)
{
  if (!conf->port)
    conf->port = 53;
  if (!conf->ressources)
    {
      LOG("Need at least one ressource \n");
      return (-1);
    }
  if (!conf->my_domain)
    {
      LOG("Need a domain name\n");
      return (-1);
    }
  return (0);
}

static int	add_ressource(t_conf *conf, char *value)
{
  t_list	*cell;
  char		*port;
  
  if (!(port = strrchr(value, ':')))
    return (-1);
  *port++ = 0;
  if (!strchr(value, ':'))
    return (-1);
  if (!(cell = list_create_cell()))
    return (-1);
  if (!conf->ressources)
    conf->ressources = cell;
  else
    list_add_cell(conf->ressources, cell);
  strcpy(cell->data, value);
  cell->info.port = atoi(port);
  DPRINTF(1, "Add ressource %s port %d\n", value,  cell->info.port);
  free(value);
  return (0);
}

static int	server_copy_param(void *my_conf, char *token, char *value)
{
  char		*buffer = 0;
  t_conf	*conf;

  conf = (t_conf *)my_conf;
  if (token)
    {
      if (!strcmp(token, "debug_level"))
	return (debug ? 0 : (debug = atoi(value)));
      if (!strcmp(token, "port"))
	return (conf->port = atoi(value));
      if (!(buffer = malloc(strlen(value)+1)))
	{
	  LOG("Memory error\n");
	  exit (-1);
	}
      strcpy(buffer, value);
      if (!strcmp(token, "chroot"))
	return ((int) (conf->chroot = buffer));
      if (!strcmp(token, "user"))
	return ((int) (conf->user = buffer));
      if (!strcmp(token, "domain"))
	return ((int) (conf->my_domain = buffer));
      if (!strcmp(token, "listen"))
	return ((int) (conf->my_ip ? 0 : (conf->my_ip = buffer)));
      if (!strcmp(token, "ressources"))
	return (add_ressource(conf, buffer));
    }
  if (buffer)
    free(buffer);
  return (-1);
}

int			get_option(int argc, char **argv, t_conf *conf)
{
  int			c;
  char			config_file[CONFIG_FILE_LEN];

  bzero(conf, sizeof(t_conf));
  config_file[0] = 0;
  debug = 0;
  while (1)
    {
      c = getopt (argc, argv, "hFf:i:d:");
      if (c == -1)
        break;
      switch (c) {
      case 'f':
	if (strlen(optarg) > (CONFIG_FILE_LEN - 10))
	  return (-1);
	strcpy(config_file, optarg);
	break;	
      case 'd':
	debug = atoi(optarg);
	break;
      case 'F':
	conf->foreground = 1;
	break;
      case 'i':
	conf->my_ip = optarg;
	break;
      case 'h':
      default :
	usage(argv[0]);
	return(-1);
      }
    }
  read_config(config_file, conf, server_copy_param, ".dns2tcpdrc");
  if (check_mandatory_param(conf) == -1)
    {
      usage(argv[0]);
      return (-1);
    }
  return (0);
}

	  
	  
