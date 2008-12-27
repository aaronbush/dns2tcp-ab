/*
** Copyright (C) 2006 Nicolas COLLIGNON
** $Id: mywin32.h,v 1.4 2007/02/13 10:31:14 collignon Exp $
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

#ifndef __MY_WIN32_H__
#define __MY_WIN32_H__

#include <winsock2.h>

typedef unsigned char uint8_t;
typedef signed char int8_t;
typedef unsigned short uint16_t;
typedef signed short int16_t;
typedef unsigned long uint32_t;
typedef signed long int32_t;

#define socket_t SOCKET

#define getpid GetCurrentProcessId

#define strncasecmp _strnicmp

#define read(f,b,l)  recv(f, b, (int) l, 0)
#define write(f,b,l) send(f, b, (int) l, 0)

#define close closesocket

extern char *optarg;
int getopt(int, char * const *, const char *);

int __inline gettimeofday(struct timeval *tv, void *bla)
{
  tv->tv_sec  = (long) time(NULL);
  tv->tv_usec = 0;
  return 0;
}

#endif
