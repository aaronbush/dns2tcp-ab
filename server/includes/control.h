/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: control.h,v 1.3 2006/01/17 13:01:59 dembour Exp $
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

#ifndef __CONTROL_H__
#define __CONTROL_H__

/* client */
typedef	struct		s_control {
  uint8_t		req;		/* first req acceptable */
  uint8_t		queue_full;	
  uint8_t		use_compress;    
  struct timeval	tv;
  char			*hash_wanted;
}			t_control;

/* packet */
typedef	struct		s_control_peer {
  struct sockaddr_in	sa;
  char			data[MAX_HOST_NAME_ENCODED];
  int			len;
  uint16_t		seq;
}			t_control_peer;


#endif
