/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: config.c,v 1.9.2.2 2008/09/02 09:16:15 dembour Exp $
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
#include <config.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef _WIN32
#include "mywin32.h"
#endif

#include "my_config.h"
#include "debug.h"

#define MAX_LINE_LEN 512

char	*extract_param(char **line, uint8_t *stop)
{
  char	*param;
  
  if ((!*line) || (! **line))
    return (0);
  param = *line;
  *stop = 1;
  if ((*line = strchr(*line, ',')))
    {
      *(*line)++ = 0;
      *stop = 0;
    }
  return (param);
}

void		remove_space(char *buffer)
{
  size_t i, j, len;

  len = strlen(buffer);
  if (!len || !buffer[0] || (buffer[0] == '#'))
    return;
  for (i=0,j=0; i<len; ++i)
    {
      if (buffer[i] > 0x20)
	{
 	  if (i != j)
	    buffer[j] = buffer[i];
	  ++j;
        }
    }
  buffer[j] = 0;
}


void		config_extract_token(FILE *file, void *conf, 
				     int (*copy_func)(void *, char *, char *))
{
  char		buffer[MAX_LINE_LEN + 1];
  char		token2[MAX_LINE_LEN + 1];
  char		*token;
  char		*value;
  char		*ptr;
  uint8_t	stop;

  token = token2;
  *token=0;
  stop = 1;
  while (fgets(buffer, MAX_LINE_LEN, file))
    {
      remove_space(buffer);
      if (!buffer[0])
	continue;
      value = buffer;
      if ((ptr = strchr(buffer, '=')))
	{
	  *ptr = 0;
	  value = ptr + 1;
	  strcpy(token, buffer);
	}
      if ((*buffer == '#') || (!*token))
	{
	  *token = 0;
	  continue;
	}
      ptr = value;
      while (((value = extract_param(&ptr, &stop))) && (*value))
	copy_func(conf, token, value);
      if (stop)
	  *token = 0;
    }
}



int	read_config(char *file, void *conf,
		    int (*copy_func)(void *, char *, char *), 
		    char *extension)
{
  FILE	*my_file;
  char	*home;

  if (!*file)
    {
      if ((!(home = getenv("HOME"))) 
	  || ((strlen(home) > (CONFIG_FILE_LEN - sizeof("/.dns2tcprc") - 10))))
	return (-1);
      snprintf(file, CONFIG_FILE_LEN-1, "%s/%s", home, extension);
    }
  if (!(my_file = fopen(file, "r")))
    {
      DPRINTF(1, "Warn cannot openning config file \'%s\'\n", file);
      return (-1);
    }
  config_extract_token(my_file, conf, copy_func);
  return (fclose(my_file));
}
