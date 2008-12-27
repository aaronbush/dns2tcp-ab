/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: auth.h,v 1.3 2006/11/17 15:50:16 dembour Exp $
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

#ifndef __AUTH_H__
#define __AUTH_H__

int login_user(t_conf *conf, void  *packet, void *buffer, int len,  struct sockaddr_in *sa);
uint16_t create_env(t_conf *conf, void *req, char *ressource, int in_len);

#endif
