/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: socket.h,v 1.1.1.1 2006/01/06 13:53:23 dembour Exp $
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

#ifndef __SOCKET_H__
#define __SOCKET_H__

#include <netinet/in.h>

int connect_socket(char *, uint16_t, int *);
int bind_socket(t_conf *);

#endif
