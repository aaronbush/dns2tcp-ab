/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: options.c,v 1.13 2007/05/29 16:46:50 dembour Exp $
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
#include <strings.h>
#include <unistd.h>
#endif

#include "client.h"
#include "my_config.h"
#include "debug.h"


static void	usage(char *name)
{
  fprintf(stderr,
    "dns2tcp v%s ( http://www.hsc.fr/ )\n"
    "Usage :%s [-c] [-z zone] [-d debug_level] [-l local-port] [-r ressource] [-f config] [server] \n"
    "\t-c\t: force use of compression\n"
    "\t-z\t: domain to use (mandatory)\n"
    "\t-d\t: debug_level (1, 2 or 3)\n"
    "\t-r\t: ressource to access\n"
    "\t-f\t: configuration file\n"
    "\t-l\t: local port to bind (mandatory if ressource defined)\n"
    "\tserver\t: DNS server to use (mandatory)\n"
    "\tIf no ressources are specified, available ressources will be printed\n",
    VERSION, name);
}

static int	check_mandatory_param(t_conf *conf)
{
  if (!conf->dns_server)
    {
      fprintf(stderr, "Missing parameter : need a dns server \n");
      return (-1);
    }
  if (!conf->domain)
    {
      fprintf(stderr, "Missing parameter : need a dns zone \n");
      return (-1);
    }
  if ((conf->ressource) && (!conf->local_port))
    {
      fprintf(stderr, "Missing parameter : need a local port \n");
      return (-1);
    }
  return (0);
}


static int	client_copy_param(void *my_conf, char *token, char *value)
{
  char		*buffer = 0;
  t_conf	*conf;

  conf = (t_conf *)my_conf;
  if (token)
    {
      if (!strcmp(token, "local_port"))
	return ((conf->local_port)? 0 : (conf->local_port = atoi(value)));
      if (!strcmp(token, "compression"))
	return ((conf->use_compression) ? 0 : (conf->use_compression = atoi(value)));
      if (!strcmp(token, "debug_level"))
	return (debug ? 0 : (debug = atoi(value)));
      if (!(buffer = malloc(strlen(value)+1)))
	{
	  fprintf(stderr, "Memory error\n");
	  exit (-1);
	}
      strcpy(buffer, value);
      if (!strcmp(token, "server"))
	return ((int) (conf->dns_server ? 0 : !!(conf->dns_server = buffer)));
      if (!strcmp(token, "domain"))
	return ((int) (conf->domain ? 0 :  !!(conf->domain = buffer)));
      if (!strcmp(token, "secret"))
	return ((int) (conf->secret ? 0 : !!(conf->secret = buffer)));
      if (!strcmp(token, "ressource"))
	return ((int) (conf->ressource ? 0 : !!(conf->ressource = buffer)));
    }
  if (buffer)
    free(buffer);
  return (-1);
}



int			get_option(int argc, char **argv, t_conf *conf)
{
  int			c;
  char			config_file[CONFIG_FILE_LEN];
  
  memset(conf, 0, sizeof(t_conf));
  memset(config_file, 0, sizeof(config_file));
  debug = 0;
  while (1)
    {
      c = getopt (argc, argv, "chv:z:s:d:l:r:f:");
      if (c == -1)
	  break;
      switch (c) {
      case 'f':
	if (strlen(optarg) > (CONFIG_FILE_LEN - 10))
	  return (-1);
	strcpy(config_file, optarg);
	break;
      case 'z':
	conf->domain = optarg;
	break;
      case 'd':
	debug = atoi(optarg);
	break;
      case 's':
	conf->secret = optarg;
	break;
      case 'r':
	conf->ressource = optarg;
	break;
      case 'l':
	  conf->local_port = atoi(optarg);
	  break;
      case 'c':
	conf->use_compression = 1;
	break;
      case 'v':
	  usage(argv[0]);
	  return (-1);
	break;
      case 'h':
      default:
	  usage(argv[0]);
	  return (-1);
      }
    }
  if (optind < argc)
      conf->dns_server = argv[optind];
  if ((*config_file) || (!conf->domain)) 
    /* we don't care if this fails if options are passed with argv[] */
    read_config(config_file, conf, client_copy_param, ".dns2tcprc");
  if (check_mandatory_param(conf) == -1)
    {
      usage(argv[0]);
      return (-1);
    }
  if (debug)
    fprintf(stderr, "debug level %d\n", debug);
  return (0);
}

	  
	  
