/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: auth.c,v 1.11 2007/06/28 12:39:47 dembour Exp $
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
#include <stdio.h>       
#ifndef _WIN32
#include <unistd.h>
#endif

#include "client.h"
#include "dns.h"
#include "myerror.h"
#include "list.h"
#include "requests.h"
#include "socket.h"
#include "base64.h"
#include "myrand.h"

int			dump_ressource(void *req, int len)
{
  char			buffer[MAX_REQ_LEN];
  struct rr_hdr		*answer;
  struct dns_hdr	*hdr;
  int			count;
  void			*ptr;
  char			*name;
  
  hdr = req;
  if (!(ptr  = jump_end_query(req, GET_16(&hdr->qdcount), len)))
    return (-1);
  name = ptr;
  printf("Available connection(s) : \n");
  for (count = GET_16(&hdr->ancount); count ; count--)
    {
      answer = jump_qname(ptr);
      if (result2data(JUMP_RR_HDR(answer), buffer, GET_16(&answer->rdlength)))
	printf("\t%s\n", buffer);
      ptr =(void *)(JUMP_RR_HDR(answer) + GET_16(&answer->rdlength));
    }
  if (!((*name & COMPRESS_FLAG_CHAR) == COMPRESS_FLAG_CHAR))
    printf("\nNote : Compression NOT available !\n");
  return (0);
}

int			list_ressources(t_conf *conf, struct sockaddr_in *sa)
{
  t_packet		query;
  char			buffer[MAX_REQ_LEN];
  char			name[MAX_HOST_NAME_ENCODED + 1];
  int			len;
  struct dns_hdr	*hdr;
  
  query.type = 0;
  query.cookie = myrand();
  query.ack_seq = myrand();
  query.seq = myrand();
  hdr = (struct dns_hdr *) buffer;
  create_req_hdr(&buffer, conf);
  data2qname(&query, PACKET_LEN, &name, conf);
  if (strlen(name) + strlen(conf->domain) >= MAX_HOST_NAME_DECODED)
    {
      MYERROR("Request too long");
      return (-1);
    }
  len = add_query((struct dns_hdr *)&buffer, JUMP_DNS_HDR(hdr), name, conf, TYPE_KEY);
  if ((len = sendto(conf->sd_udp, buffer, len,0, (struct sockaddr *)sa, sizeof(struct sockaddr))) == -1)
    {
      MYERROR("Connect error");
      return (-1);
    }
  if ((len = get_simple_reply(conf, &buffer, hdr->id)) > 0)
    {
      hdr = (struct dns_hdr *)&buffer;
      if (hdr->rcode)
	{
	  printf("Auth error = %s\n", dns_error[hdr->rcode % (MAX_DNS_ERROR-1)]);
	  return (-1);
	}
      if (dump_ressource(buffer, len))
	return (0);
    }
  return (-1);
}

uint16_t		get_cookie(t_conf *conf, void *req, int max_len)
{
  struct rr_hdr		*answer;
  struct dns_hdr	*hdr;
  void			*ptr;
  t_packet		*packet;
  char			buffer[BASE64_SIZE(MAX_ERROR_SIZE + PACKET_LEN) +1];

  hdr = req;
  if (!(ptr  = jump_end_query(req, GET_16(&hdr->qdcount), max_len)))
    return (-1);
  answer = jump_qname(ptr);
  packet = (t_packet *) buffer;
  if (result2data(JUMP_RR_HDR(answer), buffer, MIN(sizeof(buffer),GET_16(&answer->rdlength))))
    {
      if (packet->type == (AUTH|OK))
	return (packet->cookie);
      else
	{
	  buffer[sizeof(buffer)-1] = 0;
	  printf("Authentication failed remote host said : %s\n", buffer+PACKET_LEN);
	}
    }
  return (0);
}

uint16_t		connect_ressource(t_conf *conf, struct sockaddr *sa)
{
  t_packet		*query;
  char			buffer[MAX_REQ_LEN];
  char			name[MAX_HOST_NAME_ENCODED + 1];
  int			len;
  struct dns_hdr	*hdr;
  char			*ptr;
  
  query = (t_packet *)&buffer;
  query->type = AUTH;
  if (conf->use_compression)
    {
      query->type |= USE_COMPRESS;
      printf("want compress\n");
    }
  query->cookie = conf->id;
  query->seq = myrand();
  ptr = (char *)query + PACKET_LEN;
  strcpy(ptr, conf->ressource);
  data2qname(buffer, (int) (PACKET_LEN + strlen(ptr)), &name, conf);
  hdr = (struct dns_hdr *) &buffer;
  create_req_hdr(&buffer, conf);
  if (strlen(name) >= MAX_HOST_NAME_DECODED)
    {
      MYERROR("Request too long");
      return (-1);
    }
  len = add_query(hdr, JUMP_DNS_HDR(hdr), name, conf, TYPE_KEY);
  if ((len = sendto(conf->sd_udp, buffer, len,0, sa, sizeof(struct sockaddr))) == -1)
    {
      MYERROR("Connect error");
      return (-1);
    }
  if ((len = get_simple_reply(conf, &buffer, hdr->id)) > 0)
    return (get_cookie(conf, &buffer, len));
  //MYERROR("sending error");
  //  perror("");
  return (0);
}

