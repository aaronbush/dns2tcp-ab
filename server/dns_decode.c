/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: dns_decode.c,v 1.2.2.3 2008/11/03 12:07:52 dembour Exp $
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

#include <string.h>
#include <stdio.h>

#include "packet.h"
#include "dns.h"
#include "server.h"
#include "myerror.h"
#include "mystrnlen.h"
#include "log.h"
#include "debug.h"

static int	dns_strip_subdomain(char *name, t_conf *conf, struct sockaddr_in *sa)
{
  char		*ptr;
  unsigned int 	i, j, len;
  
  ptr = strstr(name, conf->my_domain);
  if (!ptr)
    {
#ifndef WORDS_BIGENDIAN
      LOG("Query from %u.%u.%u.%u for unknown domain %s",
      (unsigned int) ((sa->sin_addr.s_addr) & 0xff),
      (unsigned int) ((sa->sin_addr.s_addr >> 8) & 0xff),
      (unsigned int) ((sa->sin_addr.s_addr >> 16) & 0xff),
      (unsigned int) ((sa->sin_addr.s_addr >> 24) & 0xff), name);
#else
      LOG("Query from %u.%u.%u.%u for unknown domain %s",
      (unsigned int) ((sa->sin_addr.s_addr >> 24) & 0xff),
      (unsigned int) ((sa->sin_addr.s_addr >> 16) & 0xff),
      (unsigned int) ((sa->sin_addr.s_addr >> 8) & 0xff),
      (unsigned int) ((sa->sin_addr.s_addr) & 0xff), name);
#endif
      return (-1);
    }
  *ptr = 0;
  len = (unsigned int) (ptr - name);
  for (i=0,j=0; i<len; ++i)
    {
      if (name[i] != '.')
	{
          if (i != j)
            name[j] = name[i];
	  ++j;
	}
    }
  name[j] = 0;
  return (0);
}


/* 
   Not a RFC compatible decoder 
 return -1 if domain is incorrect 
dns_decode check max size of host
*/

int		dns_decode(char *data, char *input, char *output, t_conf *conf, 
			   struct sockaddr_in *sa)
{
  int		total_len = 0;
  uint8_t	len;
  char		*ptr;

  ptr = input;
  *output = 0;
  
  while (*ptr)
    {
      // Oups ...
      len = (uint8_t) *ptr;
      total_len += len;
      if ((len > 63) || (total_len > MAX_HOST_NAME_ENCODED))
	{
	  DPRINTF(1, "req was %u %s -> %s\n", (unsigned int) strlen(input), 
		  input, output);
	  MYERROR("NAME TOO long %d %d", len, total_len + len);
	  return (-1);
	}
      strncat(output, ptr + 1, len);
      output[total_len] = 0;
      if (len)
	{
	  if (++total_len > MAX_HOST_NAME_ENCODED)
	    return (-1);
	  strcat(output , ".");
	  len++;
	}
      ptr += (len);
    }
  if (total_len > 0)
    output[total_len -1 ] = 0;
  return (dns_strip_subdomain(output, conf, sa));
}
