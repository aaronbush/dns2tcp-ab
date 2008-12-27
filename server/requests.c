/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: requests.c,v 1.15 2007/05/30 13:04:45 dembour Exp $
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

#include <stdio.h>       
#include <string.h>
#include <sys/socket.h>

#include "server.h"
#include "dns.h"
#include "dns_decode.h"
#include "list.h"
#include "base64.h"
#include "myerror.h"
#include "queue.h"
#include "server_queue.h"
#include "mystrnlen.h"
#include "auth.h"

static uint16_t		get_type_request(void *buffer, int max_len)
{
  struct dns_hdr	*hdr;
  char 			*ptr;
  
  hdr = buffer;
  if (sizeof(struct dns_hdr) > max_len)
    return (-1);
  if (hdr->qdcount > 0)
    {
      ptr = memchr(JUMP_DNS_HDR(hdr), 0, max_len - sizeof(struct dns_hdr));
      if (ptr)
        return GET_16(&(((struct req_hdr *) (ptr+1))->qtype));
    }
  return (0);
}

void			*add_reply(struct dns_hdr *hdr, void *where, uint16_t type, char *encoded_data)
{
  struct rr_hdr		*rr;
  uint16_t		*compress;
  int			len;

  PUT_16(&hdr->ancount, GET_16(&hdr->ancount)+1);
  hdr->arcount = 0;
  compress = where;
  PUT_16(compress, sizeof(struct dns_hdr) | COMPRESS_FLAG);
  rr = where + sizeof(uint16_t);
  PUT_16(&rr->type, type);
  PUT_16(&rr->klass, CLASS_IN);
  PUT_16(&rr->ttl, 0);
  where = JUMP_RR_HDR(rr);
  strcpy(where, encoded_data);
  if (type == TYPE_TXT)
    dns_encode(where);
  len = strlen(where);
  PUT_16(&rr->rdlength,len);
  return (where + len);
}

static int		build_ressources_reply(t_conf *conf, void *buffer, 
					       int  max_len)
{
  struct dns_hdr	*hdr;
  t_list		*list;
  void			*where;
  char			buffer2[MAX_REQ_LEN];

  hdr = buffer;
  hdr->ra = 1;
  hdr->qr = 1;

  if (!(where = jump_end_query(buffer, GET_16(&hdr->qdcount), max_len)))
    return (-1);
  for (list = conf->ressources; list; list = list->next)
    {
      base64_encode(list->data, buffer2, (strchr(list->data, ':') - list->data));
      where = add_reply(hdr, where, TYPE_KEY, buffer2);
    }
  return (where - buffer);
}

static int		get_request(void *req, char *output, t_conf *conf,
				    struct sockaddr_in *sa)
{
  char			buffer[MAX_HOST_NAME_ENCODED + 1];
  int			len;
  char			*data;


  data = JUMP_DNS_HDR(req);
  if (mystrnlen(data, MAX_HOST_NAME_ENCODED + 1) > MAX_HOST_NAME_ENCODED)
    return (-1);
  if (dns_decode((char *)req, data, buffer, conf, sa) == -1)
    return (-1);
  len = base64_decode((unsigned char *)output, buffer);
  output[len] = 0;
  return (len);
}


int			build_error_reply(t_conf *conf, void *req, int max_len, char *error)
{

  struct dns_hdr	*hdr;
  void			*where;
  t_packet		*packet;
  char			buffer[BASE64_SIZE(MAX_ERROR_SIZE) + PACKET_LEN];
  char			buffer2[BASE64_SIZE(MAX_ERROR_SIZE) + PACKET_LEN];
  int			len;

  hdr = req;
  hdr->ra = 1;
  hdr->qr = 1;
 if (!(where = jump_end_query(req, GET_16(&hdr->qdcount), max_len)))
      return (-1);
  packet = (t_packet *) memset(buffer, 0, PACKET_LEN);
  packet->type = ERR;
  len = strlen(error);
  memcpy(buffer+PACKET_LEN, error, len+1);
  base64_encode(buffer, buffer2, PACKET_LEN + len);
  where = add_reply(hdr, where, TYPE_KEY, buffer2);
  return (where - req);
}

static int		get_ressources(t_conf *conf,void *req,
				       int in_len, struct sockaddr_in *sa)
{
  int			out_len = -1;
  char			buffer[MAX_HOST_NAME_ENCODED + 1];
  int			len;
  t_packet		*packet;

  if ((len = get_request(req, buffer, conf, sa)) == -1)
    return (-1);
  packet = (void *)&buffer;
  if (! packet->type)
    out_len = build_ressources_reply(conf, req, in_len);
  else
    out_len = login_user(conf, req, buffer, in_len, sa);
  if (out_len == -1)
    {
      MYERROR("parsing error\n");
      return (-1);
    }
  if ((out_len = sendto(conf->sd_udp, req, out_len, 
			0, (struct sockaddr *)sa, sizeof(struct sockaddr))) == -1)
    {
      MYERROR("send error\n");
      return (-1);
    }
  return (0);
 }

 int			get_incoming_request(t_conf *conf)
 {
   struct sockaddr_in	sa_other;
   char			buffer[MAX_REQ_LEN + 1];
   int			len;
   socklen_t		slen;
   int16_t		type;

   slen = sizeof(sa_other);
   if ((len = recvfrom(conf->sd_udp, buffer, 
		       MAX_REQ_LEN, 0, (struct sockaddr *)&sa_other, &slen)) == -1)
     return (-1);
   if (!(type = get_type_request(buffer, len)))
     return (-1);
   if (type == TYPE_KEY)
     return (get_ressources(conf,buffer, len, &sa_other));
   if (type == TYPE_TXT)
     return (queue_put_data(conf,buffer, len, &sa_other));
  return (0);
}

