/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: requests.h,v 1.2 2006/01/09 08:41:19 dembour Exp $
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

#ifndef __REQUESTS_H__
#define  __REQUESTS_H__

void	create_req_hdr(void *, t_conf *);
int	add_query(struct dns_hdr *, void *, char *, 
		  t_conf *, uint16_t );
void	data2qname(void *,int , void *, t_conf *);
int	result2data(void *, char *, int);
void	*jump_qname(void *);

int	create_req_data(t_conf *conf, struct s_simple_list *client, struct s_list *queue, char *data, int len);

struct rr_hdr	*get_reply(void *data, int len);

#endif
