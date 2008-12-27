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

#include <sys/time.h>     
#include <sys/socket.h>
#include <time.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "base64.h"
#include "server.h"
#include "dns.h"
#include "dns_decode.h"
#include "packet.h"
#include "myerror.h"
#include "requests.h"
#include "control.h"
#include "list.h"
#include "debug.h"

void		queue_dump(t_simple_list *client);

t_list          *init_queue()
{
  int           nb;
  t_list        *first;
  t_list        *list;

  if (!(first = malloc(sizeof(t_list))))
    return (0);
  list = first;
  memset(first, 0, sizeof(t_list));
  for (nb = QUEUE_SIZE - 1; nb; nb--)
    {
      if (!(list->next = malloc(sizeof(t_list))))
        return (0);
      memset(list->next, 0, sizeof(t_list));
      list->next->next = 0;
      list = list->next;
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

static int	queue_mark_received(t_list *queue, uint16_t seq)
{
  if (seq)
    {
      while ((queue) && (queue->info.num_seq != seq))
	queue = queue->next;
      if (!queue)
	return (0);
      queue->status = (queue->status == FREE) ? FREE : RECEIVED;
    }
  return (0);
}

static int		queue_copy_data(t_simple_list *client, t_list *queue, t_packet *packet, int len)
{
  void			*data;

  data = (void *)packet + PACKET_LEN;
  if ((packet->type & DATA) == DATA) 
    {
      memcpy(queue->peer.data, data, len - PACKET_LEN);
      queue->peer.len = len - PACKET_LEN;
    }
  if (packet->type == NOP)
    queue->peer.len = 0;
  if (packet->type == DESAUTH)
    return (-1);
  queue->status = USED;
  queue->peer.seq = packet->seq;
  client->control.queue_full = 0;
  if (queue == client->queue)
    client->num_seq = packet->seq;
  return (0);
}

static int		queue_send_data(t_conf *conf, t_list *queue)
{
  if ((sendto(conf->sd_udp, queue->data, queue->len, 0, 
	      (struct sockaddr *)&(queue->peer.sa), sizeof(struct sockaddr))) == -1)
    {
      MYERROR("send error len %d ", queue->len);
      perror("");
      return (-1);
    }
  queue->status = SENT;
  return (0);
}

static void		queue_reply(t_conf *conf, t_simple_list *client, 
				    t_list *queue, void *data, int data_len)
{
  struct dns_hdr	*hdr;
  void			*where;
  t_packet		*packet;
  char			buffer[MAX_REQ_LEN - DNS_HDR_SIZE - REQ_HDR_SIZE ];
  char			buffer2[MAX_REQ_LEN - DNS_HDR_SIZE -REQ_HDR_SIZE ];

  hdr = (struct dns_hdr *) queue->data;
  hdr->ra = 1;
  hdr->qr = 1;
  if (!(where = jump_end_query(hdr, GET_16(&hdr->qdcount), queue->len)))
    {
      MYERROR("parsing errror");
      memdump(hdr, queue->len);
      return ;
    }
  packet = (t_packet *)buffer;
  packet->cookie = client->cookie;
  packet->type = ACK ;
  PUT_16(&packet->seq, queue->peer.seq);
  packet->ack_seq = 0;
  if (data_len > 0)
    {
      packet->type |= DATA;
      memcpy(&buffer[PACKET_LEN], data, data_len);
    }
  if (data_len == -1)
    {
      packet->type = DESAUTH ;
      data_len = 0;
    }
  base64_encode((char *)packet, buffer2, PACKET_LEN + data_len);
  where = add_reply(hdr, where, TYPE_TXT, buffer2);
  queue->len = where - (void *)hdr;
  DPRINTF(2, "Send data [%d] data_len %d total len %d\n", queue->info.num_seq, data_len, queue->len);
  DPRINTF(3, "Data of packet [%d] is : %s \n", queue->info.num_seq, buffer2);
  queue_send_data(conf, queue);
}

static int		queue_flush_incoming_data(t_simple_list *client)
{
  t_list		*queue;

  queue = client->queue;
  while ((queue) && (queue->status != FREE))
    {
      if ((queue->peer.len) && (queue->peer.len))
	{
	  if (write(client->sd_tcp, queue->peer.data, queue->peer.len) < 0)
	    return (-1);
	  DPRINTF(2, "Flush Write %d bytes\n", queue->peer.len);
	  queue->peer.len = 0;
	}
      queue = queue->next;
    }
  return (0);
}

static int	queue_change_root(t_simple_list *client)
{
  t_list	*end;
  t_list	*new_root;
  t_list	*prev;

  
  if (client->queue->status != RECEIVED)
    return (0);
  prev = client->queue;
  for (end = client->queue; end ; end = end->next)
    {
      if (end->status != RECEIVED)
	break;
      end->status = FREE;
      end->info.num_seq = 0;
      client->control.req++;
      client->num_seq++;      
      prev = end;
    }
  if (!end)
    return (0);
  new_root = end;
  prev->next = 0;
  for (end = new_root; end->next; end = end->next)
    ;
  end->next = client->queue;
  client->queue = new_root;
  return (0);
}

int		queue_flush_outgoing_data(t_conf *conf,t_simple_list *client, int index)
{
  t_list	*queue;

  DPRINTF(2, "Flushing outgoing data\n");
  for (queue = client->queue; index-- ; queue = queue->next)
    {
      if (queue->status != USED)
	return (0);
      queue_reply(conf, client, queue, 0, 0);
      queue->status = SENT;
      client->control.req--;  
    }
  return (0);
}

/*
  Should copy paquet, mark original query cell as 'RECEIVED'
  
  if cell is USED (reply sent or prepared to be sent)
  resent the data

  if CELL is FREE (new data comming) 
	-> copy data
	-> try to flush incoming data
	-> try to change root

  if diff(first in queue, received) > SIZE -> try to flush SIZE/2 paquets

*/

static int	queue_deal_incoming_data(t_conf *conf, t_simple_list *client, t_list *queue,
					 t_packet *packet, int len)
{
  int		res = 0;

  if ((packet->ack_seq) && (queue_mark_received(client->queue, packet->ack_seq)))
    return (-1);
  if (queue)
    {
      switch (queue->status) 
	{
	case USED:
	  queue_reply(conf, client, queue, 0, 0);
	  queue->status = SENT;
	  client->control.req--;
	  break;
	case SENT:
	case RECEIVED:
	  DPRINTF(3, "SENT|RECEIVED received same req again, sending reply %d\n", queue->len);
	  res = queue_send_data(conf, queue);
	  break;
	case FREE:
	  DPRINTF(3, "recv new packt id %d\n", packet->seq);
	  res = queue_copy_data(client, queue, packet, len);
	  if (queue_flush_incoming_data(client) < 0)
	    return (-1);
	  if (client->queue->status == RECEIVED)
	    queue_change_root(client);	      
	  break;
	}
      if ((packet->seq > client->num_seq)
	  &&  ((packet->seq -client->num_seq ) > FLUSH_TRIGGER))
	queue_flush_outgoing_data(conf, client, (packet->seq - client->num_seq )/2);
      return (res);
    }
  return (-1);
}

int			queue_read_tcp(t_conf *conf, t_simple_list *client)
{
  char			buffer[ MAX_TXT_DATA(DNS_HDR_SIZE + REQ_HDR_SIZE) ];
  t_list		*queue;
  char			*end_query;
  struct dns_hdr	*hdr;
  int			len;
  
  for (queue = client->queue; queue; queue = queue->next)
    {
      if (queue->status == FREE)
	break;
      if (queue->status == USED)
	{
	  hdr = (struct dns_hdr *)queue->data;
	  if ((end_query = jump_end_query(hdr, GET_16(&hdr->qdcount), queue->len)))
	    {
	      len = read(client->sd_tcp, buffer, 
			 TXT_DATA_AVAILABLE((end_query - (char *)hdr), strlen(JUMP_DNS_HDR(hdr))) - sizeof(t_packet));
	      if (len < 1)
		{
		  queue_reply(conf, client, queue, 0, -1);
		  return (-1);
		}
	      DPRINTF(3, "Read tcp %d bytes\n", len);
	      queue_reply(conf, client, queue, buffer, len);
	      return (0);
	    }
	  DPRINTF(1, "query parsing error\n");
	}
    }
  client->control.queue_full = 1;
  return (0);
}

void		queue_dump(t_simple_list *client)
{
  t_list	*queue;

  while (client)
    {
      queue = client->queue;
      printf("client 0x%x\n", client->cookie);
      while (queue)
	{
	  printf("{seq=%d:stat=%s} ", queue->info.num_seq, 
		 (queue->status == 0) ? "F" : (queue->status == USED )? "U" :"S" );
	  queue = queue->next;
	}
      printf("\n");
      client = client->next;
    }
}

static t_list	*get_cell_in_queue(t_list *queue, int diff)
{
  while ((queue) && (diff--))
    queue = queue->next;
  return (queue);
}

static int	queue_copy_query(t_list *queue, t_packet *packet, void *buffer, int in_len, struct sockaddr_in *sa)
{
  if (queue->status == FREE)
    {
      memcpy(queue->data, buffer, in_len);
      memcpy(&(queue->peer.sa), sa, sizeof(struct sockaddr_in)); 
      queue->len = in_len;	
      queue->info.num_seq = packet->seq;	
      return (0);
    }
  /* Copy DNS transaction ID */
  memcpy(queue->data, buffer, sizeof(uint16_t)); 
  memcpy(&(queue->peer.sa), sa, sizeof(struct sockaddr_in)); 
  return (0);
}

static int		build_error(t_conf *conf, char *buffer, int in_len, struct sockaddr_in *sa, int code)
{
  struct dns_hdr	*hdr;  
  
  hdr = (struct dns_hdr *) buffer;

  hdr->ra = 1;
  hdr->qr = 1;
  hdr->rcode = code;
  if ((sendto(conf->sd_udp, buffer, in_len, 0, (struct sockaddr *)sa, sizeof(struct sockaddr))) == -1)
    MYERROR("sendto error");
  return (-1);
}

void			queue_update_timer(t_simple_list *client)
{
  struct timeval	tv;
  struct timezone	tz;
   
  if (!(gettimeofday(&tv, &tz)))
    {    
      client->control.tv.tv_sec = tv.tv_sec + CLIENT_TIMEOUT;
      client->control.tv.tv_usec = tv.tv_usec;
    }
}

/*
 queue_put_data
 
     -> decode request
     -> Look for client
        update the client timer
     -> put data in queue
     -> deal incoming data (queue_deal_incoming_data)
     and return
*/

int		queue_put_data(t_conf *conf, char *buffer, int in_len, struct sockaddr_in *sa)
{
  char		name[MAX_HOST_NAME_ENCODED];
  char		tmp[MAX_HOST_NAME_ENCODED];
  t_packet	*packet;
  t_simple_list	*client;
  t_list	*queue;
  int		len;
  int		diff = 0;
  uint16_t      seq_tmp;

  if (dns_decode(buffer, buffer + DNS_HDR_SIZE, tmp, conf, sa) == -1)
    return (-1); /* Bad domain -> silent DROP */
  len = base64_decode((unsigned char *)name, tmp);
  if (PACKET_LEN > len)
    return (-1);
  packet = (t_packet *)name;
  seq_tmp = GET_16(&(packet->seq)) ; packet->seq = seq_tmp;
  seq_tmp = GET_16(&(packet->ack_seq)) ; packet->ack_seq = seq_tmp;
  DPRINTF(2, "Received [%d] data_len %d\n", packet->seq, len - PACKET_LEN);
  DPRINTF(3, "Data of packet [%d] is %s\n", packet->seq, tmp);
  for (client = conf->client; client; client = client->next)
    { 
      if (packet->cookie == client->cookie)
	{
	  if (client->sd_tcp < 0)
	    return (0); /* slient drop */
	  queue_update_timer(client);
	  queue = client->queue;
	  if (client->num_seq > packet->seq) /*  seq must not be 0 */
	    diff = ((MAX_SEQ - client->num_seq) + packet->seq ); 
	  else
	    diff = packet->seq - client->num_seq ;
	  DPRINTF(2, "diff = %d\n", diff);
	  if ((diff > QUEUE_SIZE) || (!packet->seq))
	    {
	      DPRINTF(3, "seq %d not good diff %d\n", packet->seq, diff);
	      //queue_dump(client);
	      return (-1); /* not in seq */
	    }
	  if ((queue = get_cell_in_queue(queue, diff)))
	    {
	      queue_copy_query(queue, packet, buffer, in_len, sa);
	      if (queue_deal_incoming_data(conf, client, queue, packet, len))
		{
		  close(client->sd_tcp);
		  return (delete_client(conf, client));
		}
	    }
	  else 
	    /* Cell not found (reply already received or cell lost ? ) */
	    return (build_error(conf, buffer, in_len, sa, RCODE_NAME_ERR));
	  break;
	}
    }
  if (!client)
    {
      DPRINTF(3, "Not a client 0x%x", packet->cookie);
      return (build_error(conf, buffer, in_len, sa, RCODE_REFUSED));
    }
  return (0); // Silent DROP 
}
