/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: dns.c,v 1.9.2.1 2008/09/01 12:49:08 dembour Exp $
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
#include "myerror.h"
#include "mystrnlen.h"
#include "debug.h"


const char	*dns_error[MAX_DNS_ERROR] = {
  "No error",
  "Format error",
  "Server failure",
  "Name error",
  "Not implemented",  
  "Request refused",
};

char		*jump_qname(void *ptr)
{
  char		*name;
  
  name = ptr;
  while (*name)
    {
      if ((*name & COMPRESS_FLAG_CHAR) == COMPRESS_FLAG_CHAR)
	return (name + 2);
      name++;
    }
  return (name + 1);
}


void			*jump_end_query(void *buffer, int nb, int max_len)
{
  void			*tmp;
  void			*max_ptr;
  int			len;

  max_ptr = ((char *)buffer) + max_len + DNS_HDR_SIZE;
  tmp = ((char *)buffer) + DNS_HDR_SIZE;
  while ((nb--) && (tmp <= max_ptr))
    {
      if ((len = mystrnlen(tmp , MAX_HOST_NAME_ENCODED+1)) 
	  > MAX_HOST_NAME_ENCODED)
	{
	  MYERROR("Host name too long (%d)\n", len);
	  return (0);
	}
      tmp = jump_qname(tmp) +  REQ_HDR_SIZE;
    }
  return ((tmp <= max_ptr) ? tmp : 0);
}

static unsigned int	search_dot(char *buffer)
{
  unsigned int		len = 0;
  
  while ((buffer[len] != 0) 
	 &&  (buffer[len] != '.'))
      len++;
  return (len);
}

void		dns_encode(char *data)
{
  char		buffer2[MAX_REQ_LEN];
  int		len;
  char		*buffer = buffer2;

  strcpy(buffer, data);
  do 
    {
      len = search_dot(buffer);
      if (len < 64)
	{
	  *data = (char) len;
	  if (len)
	    strncpy(data + 1, buffer, len);
	  if (buffer[len])
	    buffer++;
	}
      else
	{
	  len = 63;
	  *data = (char) len;
	  strncpy(data + 1, buffer, len);
	}
      buffer += len;
      data += len + 1;
    } while (len);
}

void		dns_simple_decode(char *input, char *output, int max_len)
{
  uint8_t	len;
  char		*ptr;
  int		total_len =0;
  
  ptr = input;
  *output = 0;
  while (*ptr)
    {
      len = (uint8_t) *ptr;
      total_len +=len;
      if (total_len > max_len)
	break;
      strncat(output, ptr + 1, len);
      output[total_len] = 0;
      ptr += (len + 1);
    }
}
