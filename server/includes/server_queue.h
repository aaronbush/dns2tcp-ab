/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: server_queue.h,v 1.3 2006/01/17 13:01:59 dembour Exp $
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

#ifndef __SERVER_QUEUE_H__
#define __SERVER_QUEUE_H__

#include <sys/time.h>
#include <time.h>


int	queue_put_data(t_conf *conf, char *buffer, int in_len, struct sockaddr_in *sa);
t_list *init_queue();
int	queue_read_tcp(t_conf *conf, t_simple_list *client);
int	queue_delete_zombie(t_conf * conf);
void	queue_update_timer(struct s_simple_list *client);
int	delete_queue(struct s_list *queue);

#endif
