/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: dns_decode.h,v 1.2 2007/02/02 16:56:41 dembour Exp $
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

#ifndef __DNS_DECODE_H__
#define __DNS_DECODE_H__

int	dns_decode(char *, char *, char *, t_conf *, struct sockaddr_in *);

#endif
