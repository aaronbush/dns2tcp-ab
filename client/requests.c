/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: requests.c,v 1.13 2007/06/18 09:08:34 dembour Exp $
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

#include <string.h>
#ifndef _WIN32
#include <strings.h>
#endif

#include "client.h"
#include "base64.h"
#include "dns.h"
#include "myrand.h"
#include "list.h"
#include "myerror.h"
#include "requests.h"
#include "debug.h"

void			create_req_hdr(void *buffer, t_conf *conf)
{
  struct dns_hdr	*hdr;

  hdr = (struct dns_hdr *)buffer;
  memset(buffer, 0, sizeof(struct dns_hdr));
  hdr->id = myrand();
  hdr->rd = 1;
}

int			add_query(struct dns_hdr *hdr, void *end, char *name, 
				  t_conf *conf, uint16_t type)
{
  struct req_hdr	*req;
  size_t		len;

  len = strlen(name);
  if ((len > MAX_HOST_NAME_ENCODED)
     || ( (((char *)end) + len + REQ_HDR_SIZE + 1) > ((char *)hdr + MAX_REQ_LEN)))
    return (-1);
  if (MAX_REQ_LEN < (sizeof(struct dns_hdr) + 
	     sizeof (struct req_hdr) + len + len/63 + 1))
    return (-1);
  PUT_16(&hdr->qdcount, GET_16(&hdr->qdcount)+1);
  strcpy(end , name);
  req = (struct req_hdr *) (((char *) end) + strlen(end) + 1);
  PUT_16(&req->qtype, type);
  PUT_16(&req->qclass, CLASS_IN);

  return ((int) (JUMP_REQ_HDR(req) - (char *)(hdr)));
}

void	data2qname(void *data,int  len, void *output, t_conf *conf)
{
  base64_encode((char *)data,output,  len);
  strcat(output, ".");
  strcat(output, conf->domain);
  DPRINTF(3, "Data was %s\n", (char *)output);
  dns_encode(output);
}

int		result2data(void *data, char *output, int len)
{
  char		buffer[MAX_REQ_LEN + 1];
  
  if (len > MAX_REQ_LEN)
    return (-1);
  strncpy(buffer,data, len);
  buffer[len] = 0;
  len = base64_decode((unsigned char *)output, buffer);
  output[len] = 0;
  return (len);
}

struct rr_hdr		*get_reply(void *data, int len)
{
  struct dns_hdr	*hdr;
  struct rr_hdr		*reply;
  char			*ptr;
  
  hdr = (struct dns_hdr *) data;
  if (!(reply = jump_end_query(data, GET_16(&hdr->qdcount), len)))
    {
      MYERROR("parsing error");
      return (0);
    }
  reply = jump_qname(reply);
  ptr = (char *)(JUMP_RR_HDR(reply));
  if (((ptr - (char *) hdr) + GET_16(&reply->rdlength)) > len)
    {
      MYERROR("Packet malformed truncated ?\n");
      memdump(data, len);
      return (0);
    }
  ptr[GET_16(&reply->rdlength)] = 0;
  return (reply);
}

int	create_req_data(t_conf *conf, t_simple_list *client, t_list *queue, char *data, int len)
{
  t_packet		*query;
  struct dns_hdr	*hdr;
  char			*ptr;
  char			name[MAX_HOST_NAME_ENCODED];

  query = (t_packet *) (queue->data);
  if (!len)
    query->type = NOP;
  else
    {
      if (len > 0)
	query->type = DATA;
      else
	{
	  DPRINTF(1, "send desauth\n");
	  query->type = DESAUTH;
	  len = 0;
	}
    }
  query->cookie = client->cookie;
  PUT_16(&query->seq,client->num_seq);
  PUT_16(&query->ack_seq,queue->peer.ack_seq);

  queue->info.num_seq = client->num_seq;
  ptr = ((char *)query) + PACKET_LEN;
  memcpy(ptr, data, len);
  data2qname(query, PACKET_LEN + len, &name, conf);
  hdr = (struct dns_hdr *) queue->data;
  create_req_hdr(hdr, conf);
  DPRINTF(2, "Send data [%d] ack [%d] len = %d id = 0x%x\n", client->num_seq, 
	  queue->peer.ack_seq, len, hdr->id);
  if (strlen(name) > MAX_HOST_NAME_ENCODED)
    {
      MYERROR("Request too long %u pour %s" , (unsigned int) strlen(name), 
	      name);
      return (0);
    }
  if ((queue->len = add_query(hdr, JUMP_DNS_HDR(hdr), name , conf, TYPE_TXT)))
    return (len);
  return (0);
}
