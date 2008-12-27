/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: queue.c,v 1.17 2007/06/18 09:08:34 dembour Exp $
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#ifndef _WIN32
#include <unistd.h>
#include <sys/time.h>
#else
#include "mywin32.h"
#endif

#include "dns.h"
#include "list.h"
#include "client.h"
#include "myerror.h"
#include "requests.h"
#include "myrand.h"
#include "debug.h"

t_list		*init_queue()
{
  int		nb;
  t_list	*first;
  t_list	*queue;

  if (!(first = malloc(sizeof(t_list))))
    return (0);
  queue = first;
  memset(first, 0, sizeof(t_list));
  for (nb = QUEUE_SIZE - 1; nb; nb--)
    {
      if (!(queue->next = malloc(sizeof(t_list))))
	return (0);
      memset(queue->next, 0, sizeof(t_list));
      queue->next->next = 0;
      queue = queue->next;
    }
  return (first);
}

int		delete_queue(t_list *queue)
{
  t_list	*tmp;
  t_list	*tmp2;

  if (!queue)
    return (-1);
  tmp = queue;
  while (tmp)
    {
      tmp2 = tmp;
      tmp = tmp2->next;
      free(tmp2);
    }
  return (0);
}

int			queue_send(t_conf *conf, t_simple_list *client, t_list *queue)
{
  int			out_len;
  struct timeval	tv;
  
  if ((out_len = sendto(conf->sd_udp, queue->data, queue->len,
			0, (struct sockaddr *)&(client->control.peer), 
			sizeof(struct sockaddr))) == -1)
     {
       queue->status = FREE;
       MYERROR("send error\n");
       //       perror("");
       return (-1);
     }
  if (gettimeofday(&tv, NULL))
    {
      MYERROR("Timer error");
      return (-1);
    }
  queue->timeout.tv_sec = tv.tv_sec + REPLY_TIMEOUT;
  queue->timeout.tv_usec = tv.tv_usec;
  return (0);
}

int			queue_resend(t_conf *conf, t_simple_list *client, t_list *queue)
{
  struct dns_hdr	*hdr;

  hdr = (struct dns_hdr *)queue->data;
  hdr->id = myrand();
  queue->peer.id = hdr->id;
  
  DPRINTF(3, "Queue resend seq %d id = 0x%x \n", queue->info.num_seq, queue->peer.id);
  queue_send(conf, client, queue);
  return (0);
}

int			check_for_resent(t_conf *conf)
{
  t_simple_list		*client;
  struct timeval	tv;
  t_list		*queue;
  
  if (gettimeofday(&tv, NULL))
    {
      MYERROR("Timer error");
      return (-1);
    }
  for (client = conf->client; client; client = client->next)
    for (queue = client->queue; queue; queue = queue->next)
      {
	if (queue->status == SENT)
	  {
	    if (queue->timeout.tv_sec < tv.tv_sec) 
	      //		(queue->timeout.tv_usec < tv.tv_usec))
	      {
		queue_resend(conf, client, queue);
	      }
	  }
      }
  return (0);
}

void		queue_dump(t_simple_list *client)
{
  t_list        *queue;
  
  if (debug > 1)
    {
      printf("Client 0x%x :\n", client->cookie);
      printf ("queue dump :");
      printf ("n.pen :%d d.pend %d  {seq:seq_ack:status}\n", 
	      client->control.nop_pending,
	      client->control.data_pending
	      );
      for (queue = client->queue; queue; queue = queue->next)
	{
	  printf("{seq=%d:ack=%d:stat=%s} ", 
		 queue->info.num_seq,
		 queue->peer.ack_seq ,
		 (queue->status == FREE) ? "F" : "U");
	}
      printf("\n");
    }
}

int             queue_change_root(t_simple_list *client, t_list *new_root)
{
  t_list        *end;
  t_list	*prev;

  prev = client->queue;
  if (new_root->next)
    {
      for (end = client->queue ; end != new_root; end = end->next)
	{
	  end->peer.ack_seq = 0;	  
	  end->status = FREE;
	  prev = end;
	}
      prev->next = 0;
      for (end = new_root->next; end->next; end = end->next)
        ;
      end->next = client->queue;
      client->queue = new_root;
    }
  else
    for (end = client->queue; end->next ; end = end->next)
      {
	end->status = FREE;
	end->peer.ack_seq = 0;	  
      }
    return (0);
}

/* should analyse data before copy */

int			extract_data(t_conf *conf, t_simple_list *client, t_list *queue)
{
  char			buffer[MAX_REQ_LEN - DNS_HDR_SIZE - REQ_HDR_SIZE];
  char			name[MAX_REQ_LEN - DNS_HDR_SIZE - REQ_HDR_SIZE];
  struct rr_hdr		*reply;
  t_packet		*packet;
  int			len;
  uint16_t              seq_tmp;

  if (!(reply = get_reply(queue->data, queue->len)))
    return (-1);
  dns_simple_decode(JUMP_RR_HDR(reply), buffer, 
		    DECODED_LEN((queue->len - (int) (JUMP_RR_HDR(reply) - queue->data)) + 1));

  DPRINTF(3, "dns_decode [%d] = %s\n",queue->info.num_seq, buffer);
  if ((len = base64_decode((unsigned char *)name, buffer)))
    {
      packet = (t_packet *)name;
      seq_tmp = ntohs(packet->seq); packet->seq = seq_tmp;
      queue->info.num_seq = packet->seq;
      if (packet->type == DESAUTH)
	{
	  DPRINTF(1, "Received desauth\n");
	  delete_client(conf, client);
	  return (-1);
	}
      if (queue->peer.type == DATA)
	client->control.data_pending--;
      else
	client->control.nop_pending--;
      if ((packet->type & DATA) != DATA)
	return (0);
      if ((len - PACKET_LEN) < 0)
	{
	  MYERROR("bug ! reply len = %d\n", len);
	  printf("encode = %s -> %s\n ... dumping reply and calling while(1); \n", 
		 (char *)(JUMP_RR_HDR(reply)),  (char *)buffer);
	  memdump(queue->data, queue->len);
	  while(1);
	}
      DPRINTF(2, "Write [%d] %d\n", packet->seq, len - PACKET_LEN);
      write(client->sd_tcp, &name[PACKET_LEN], len - PACKET_LEN);
    }
  return (0);
}

t_list		*queue_find_empty_data_cell(t_simple_list *client)
{
  t_list	*queue;

  queue = client->queue;
  while ((queue) && (queue->status != FREE))
    queue = queue->next;
  if (!queue)
    {
      MYERROR("QUEUE ERROR should not happen");
      while (1);
      return (0);
    }
  return (queue);
}

int		queue_prepare_ack(t_list *queue, uint16_t seq)
{
  while (queue)
    {
      if (!(queue->peer.ack_seq))
	return ((queue->peer.ack_seq = seq));
      queue = queue->next;
    } 
  return (0);
}

int		queue_flush(t_conf *conf, t_simple_list *client)
{
  t_list	*queue;
  t_list	*free_cell;

  queue = client->queue;
  if (!(free_cell = queue_find_empty_data_cell(client)))
    return (-1);
  while ((queue) && (queue->status == RECEIVED))
    {
      if (!free_cell)
	{
	  MYERROR("Queue design is too small\n");
	  queue_dump(client);
	  while (1);
	  return (-1);
	}
      queue_prepare_ack(free_cell,queue->info.num_seq);
      if (extract_data(conf, client, queue) == -1)
	return (-1);
      queue = queue->next;
      free_cell = free_cell->next;
    }
  if (queue == client->queue)
    return (-1);
  return (queue_change_root(client, queue));
}


int			queue_put_nop(t_conf *conf, t_simple_list *client)
{
  t_list		*queue;
  int			len;
  struct dns_hdr	*hdr;

  while (client->control.nop_pending < NOP_SIZE)
    {
      if ((queue = queue_find_empty_data_cell(client)))
	{
	  client->num_seq++;
	  len = create_req_data(conf, client, queue, 0, 0);
	  if (queue_send(conf, client, queue) == -1)
	    {
	      client->num_seq--;
	      return (-1);
	    }
	  client->control.nop_pending++;
	  queue->peer.type = NOP;
	  queue->status = SENT;
	  hdr = (struct dns_hdr *)queue->data;
	  queue->peer.id = hdr->id;
	  return (0);
	}
    }
  return (-1);
}


/* TODO check packet validity */

int			queue_get_udp_data(t_conf *conf, t_simple_list *client)
{
  char			buffer[MAX_REQ_LEN + 1];
  struct dns_hdr	*hdr;
  int			len;
  t_list		*queue;
  
  buffer[MAX_REQ_LEN] = 0;
  len = read(conf->sd_udp, buffer, MAX_REQ_LEN);
  hdr = (struct dns_hdr *) buffer;
  
  for (; client; client = client->next)
    {
      for (queue = client->queue; queue; queue = queue->next)
	{
	  if ((queue->status == SENT) && (queue->peer.id == hdr->id))
	    {
	      if (hdr->rcode)
		{
		  if (hdr->rcode == RCODE_NAME_ERR) 
		    {
		      /* Reply already sent and acked by server
			 Bug ?
		      */
		      if (client->control.cumul_errors++ > MAX_CLIENT_ERROR)
			{
			  DPRINTF(1, "Too many packet lost by server. Reseting connection ...\n");
			  return (delete_client(conf, client));
			}
		    }
		  DPRINTF(2, "Connection reject code %d id = 0x%x (%s)\n", hdr->rcode, hdr->id,
			  (hdr->rcode == RCODE_REFUSED) ? "Connection Lost" :  /* state not found */
			  (hdr->rcode == RCODE_NAME_ERR) ? "Query not found or already done" : "" /* already replied */
			  );
		  return (0);
		}
	      DPRINTF(2, "Received [%d] id=0x%x\n", queue->info.num_seq, hdr->id);
	      client->control.cumul_errors = 0;
	      memcpy(queue->data, buffer, len);
	      queue->data[len] = 0;
	      queue->status = RECEIVED;
	      queue->len = len;
	      queue_flush(conf, client);
	      return (0);
	    }
	}
    }
  DPRINTF(2, "received reply for unknow request 0x%x \n",  hdr->id);
  return (0);
}

int			queue_get_tcp_data(t_conf *conf, t_simple_list *client)
{
  t_list		*queue;
  int			len;
  char			buffer[MAX_HOST_NAME_ENCODED + 1];
  size_t		max_len;
  struct dns_hdr	*hdr;

  max_len = MAX_QNAME_DATA(conf->domain) - PACKET_LEN;
  /* Should exit if  !queue */
  if ((queue = queue_find_empty_data_cell(client)))
    {
      if ((client->control.data_pending >= MAX_DATA_SIZE)
	  || (client->control.data_pending + client->control.nop_pending >= WINDOW_SIZE))
	{
	  DPRINTF(1, "Warning Window size full waiting to flush ...\n");
	  return (0);
	}
      client->num_seq++;
      if (!((len = read(client->sd_tcp, buffer, max_len)) > 0))
	{
	  create_req_data(conf, client, queue, 0, -1);
	  queue_send(conf, client, queue);
	  return (-1); 
	}
      DPRINTF(3, "Read tcp %d bytes on sd %d\n", len, client->sd_tcp);
      len = create_req_data(conf, client, queue, buffer, len);
      if (queue_send(conf, client, queue) == -1)
	return (-1);
      client->control.data_pending++;
      queue->peer.type = DATA;
      hdr = (struct dns_hdr *) queue->data;
      queue->peer.id = hdr->id;
      queue->status = SENT;
    }
  return (0);
}
