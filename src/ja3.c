/*
 * Copyright (c) 2021 Jan Gru
 * All rights reserved.
 * BSD 3-Clause License
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <openssl/ssl.h>
#include <openssl/md5.h>

#include "ja3.h"

/* TLS constants */

/* Version boundaries */
#define SSL_MIN_GOOD_VERSION 0x002
#define SSL_MAX_GOOD_VERSION 0x304
/* Lengths of parts */
#define TLS_HANDSHAKE_RECORD_SIZE 0x5
#define TLS_HANDSHAKE_SIZE 0x06
#define TLS_RANDOM_SIZE 0x20
/* Offsets relative to TCP segment start */
#define OFFSET_TLS_RECORD_TYPE 0x0
#define OFFSET_TLS_RECORD_VERSION_MAJOR 0x1
#define OFFSET_TLS_RECORD_VERSION_MINOR 0x2
#define OFFSET_TLS_RECORD_PAYLOAD_len 0x3

#define OFFSET_TLS_HANDSHAKE_TYPE 0x5
#define OFFSET_TLS_HANDSHAKE_PAYLOAD_len 0x6
#define OFFSET_TLS_SESSION_ID_LEN (TLS_HANDSHAKE_RECORD_SIZE + TLS_HANDSHAKE_SIZE + TLS_RANDOM_SIZE) //0x2b
#define OFFSET_TLS_SESSION_ID (OFFSET_TLS_SESSION_ID_LEN + 1)                                        // 0x2c
#define OFFSET_TLS_CLIENT_HELLO_CIPHER_SUITES_len 0x52
#define OFFSET_TLS_CLIENT_HELLO_CIPHER_SUITES 0x53

#define OFFSET_HELLO_VERSION 0x9
#define OFFSET_SESSION_lenGTH 0x2b
#define OFFSET_CIPHER_LIST 0x4c

/* Values */
#define TLS_HANDSHAKE 0x16
#define TLS_CLIENT_HELLO 0x1
#define TLS_SERVER_HELLO 0x2

/* Extended Hello message */
/* See https://tools.ietf.org/html/rfc3546#section-2.1 */
#define EXT_SNI 0
#define EXT_MAX_FRAG_LEN 1
#define EXT_CLIENT_CERT_URL 2
#define EXT_TRUSTED_CA_KEYS 3
#define EXT_TRUNCATED_HMAC 4
#define EXT_STATUS_REQ 5

#define SNI_EXT_TYPE 0
#define SNI_DNS_HOSTNAME_TYPE 0
/* Supported groups */
#define EXT_TYPE_EC_GROUPS 10
/* EC Point formats */
#define EXT_TYPE_EC_POINT_FMTS 11

#define IS_DEBUG 0

// GREASE_TABLE Ref: https://tools.ietf.org/html/draft-davidben-tls-grease-00
const u_int16_t GREASE_TABLE[] = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa};
const uint8_t GREASE_len = 0x10;

static int is_in_grease(u_int16_t v)
{
  for (int i = 0; i < GREASE_len; ++i)
  {
    if (v == GREASE_TABLE[i])
    {
      return 1;
    }
  }
  return 0;
}

void md5_to_str(u_char* md, char* hex_str){
  /* Constructs hex string */ 
  for(int i = 0; i < 16; ++i)
    sprintf(&hex_str[i*2], "%02x", (unsigned int)md[i]);
}

u_int16_t add_cipher_suites(const u_char *payload, const u_int16_t PAYLOAD_LEN, char *buf, const u_int16_t BUF_LEN)
{
  /* Locate cipher suites */
  uint8_t sid_len = payload[OFFSET_TLS_SESSION_ID_LEN];
  u_int cs_offset = OFFSET_TLS_SESSION_ID_LEN + sizeof(sid_len) + sid_len;

  if (cs_offset > PAYLOAD_LEN)
  {
    /* Index to large */
    return -1;
  }

  /* Decodes cipher suites */
  u_int16_t cs_len = payload[cs_offset] << 8 | payload[cs_offset + 1];

  if ((cs_offset + cs_len) > PAYLOAD_LEN)
  {
    /* Index to large */
    return -1;
  }

  u_int16_t num_ciphers = cs_len / 2;
  //u_int16_t cipher_suites[num_ciphers];
  u_int cs_start = cs_offset + 2; /* Skips len */
  int added = 0;

  for (int i = 0; i < num_ciphers; ++i)
  {
    u_int16_t cs = payload[cs_start + i * 2] << 8 | payload[cs_start + i * 2 + 1];
    /* Skip meaningless GREASE cipher specs */
    if (!is_in_grease(cs))
    {
      snprintf(buf + strlen(buf), BUF_LEN - strlen(buf), added == 0 ? "%d" : "-%d", cs);
      added++;
    }
  }
  snprintf(buf + strlen(buf), BUF_LEN - strlen(buf), "%c", ',');

  /* Return offset after cipher suites */
  /* Offset to CS start + 2 bytes len of CS + length of all cs */
  return (cs_offset + 2 + cs_len);
}

int add_version(const u_char *payload, char *buf, const u_int16_t len)
{

  /* Checks TLS version in TLS header*/
  u_int16_t tls_version = payload[OFFSET_TLS_RECORD_VERSION_MAJOR] << 8 | payload[OFFSET_TLS_RECORD_VERSION_MINOR];
  if (tls_version < SSL_MIN_GOOD_VERSION || tls_version > SSL_MAX_GOOD_VERSION)
  {
    return 1;
  }

  /*Checks, TLS version in TLS hello message */
  u_int16_t hello_version = payload[OFFSET_HELLO_VERSION] << 8 | payload[OFFSET_HELLO_VERSION + 1];
  if (tls_version < SSL_MIN_GOOD_VERSION || tls_version > SSL_MAX_GOOD_VERSION ||
      hello_version < SSL_MIN_GOOD_VERSION || hello_version > SSL_MAX_GOOD_VERSION)
  {
    return 1;
  }
  if (IS_DEBUG && tls_version != hello_version)
  {
    printf("TLS Version mismatch - TLS v. 0x%x vs. Hello v. 0x%x\n", tls_version, hello_version);
  }
  /* Adds version to ja3-string */
  snprintf(buf, len, "%d,", hello_version);
  return 0;
}

u_int16_t get_extension_offset(const u_char *payload, u_int16_t compr_offset)
{
  uint8_t compr_len = payload[compr_offset];
  /* Return offset after compression methods */
  /* Offset to compr length, skip byte specifying length + bytes of compr methods */
  return (compr_offset + 1 + compr_len);
}

int add_extensions(const u_char *payload, const u_int16_t ext_offset, const u_int16_t PAYLOAD_LEN, ja3_type type, char *buf, const u_int16_t BUF_LEN)
{
  u_int16_t ext_total_len = payload[ext_offset] << 8 | payload[ext_offset + 1];
  u_int16_t cur_off = ext_offset + sizeof(ext_total_len);

  /* No extensions and therefore no EC parameters present */
  if (ext_total_len == 0)
  {
    snprintf(buf + strlen(buf), BUF_LEN - strlen(buf), "%s", ",,");
    return -1;
  }
  /* Temporary, generously sized extension string */
  char extensions[ext_total_len * 5];
  /* Initialize values */
  memset(extensions, 0, sizeof(extensions));

  char *ec_buf = NULL;
  char *pf_buf = NULL;

  u_int added = 0;

  /* Parse each extension */
  while (cur_off < ext_offset + sizeof(ext_total_len) + ext_total_len)
  {
    /* Retrieves extentsion type */
    u_int16_t ext_type = payload[cur_off] << 8 | payload[cur_off + 1];

    cur_off += sizeof(ext_type);
    /* Retrieves data length of curr extension */
    u_int16_t ext_len = payload[cur_off] << 8 | payload[cur_off + 1];
    cur_off += sizeof(ext_len);

    /* Skip, if GREASE type */
    if (is_in_grease(ext_type))
    {
      cur_off += ext_len;
      continue;
    }
    else
    {
      u_int cur_es_len = strlen(extensions);

      char fmt[4] = "-%d";
      /* Do not prepend - for first elem */
      if (added == 0)
      {
        strcpy(fmt, "%d");
      }

      snprintf(extensions + cur_es_len, ext_total_len - cur_es_len, added == 0 ? "%d" : "-%d", ext_type);
      added++;
    }

    /* Handles supported groups extension, which will be added as separate field */
    if (ext_type == EXT_TYPE_EC_GROUPS && type == CLIENT)
    {
      u_int16_t ec_len = payload[cur_off] << 8 | payload[cur_off + 1];
      u_int16_t ec_off = cur_off + sizeof(ec_len);

      /* Skip if there are no supported groups specified*/
      if (ec_len == 0)
      {
        continue;
      }

      /* Allocates char buffer for elliptic curves */
      /* Each EC is a word, so max. 5 chars will be needed */
      u_int ec_buf_len = ec_len * 5;
      ec_buf = malloc(sizeof(u_char) * ec_buf_len);
      memset(ec_buf, 0, ec_buf_len);

      /* Checks, array boundaries */
      if (ec_off + ec_len < PAYLOAD_LEN)
      {
        u_int ec_add_cnt = 0;

        /* Parse each supported group */
        for (int i = 0; i < ec_len / 2; ++i)
        {
          u_int16_t ec = payload[ec_off + i * 2] << 8 | payload[ec_off + i * 2 + 1];

          /* Add result, if not GREASE EC */
          if (!is_in_grease(ec))
          {
            snprintf(ec_buf + strlen(ec_buf), ec_buf_len - strlen(ec_buf), ec_add_cnt == 0 ? "%d" : "-%d", ec);
            ec_add_cnt++;
          }
        }
      }
    }

    /* Handles EC point formats, which will be added as separate field */
    if (ext_type == EXT_TYPE_EC_POINT_FMTS && type == CLIENT)
    {
      u_int8_t pf_len = payload[cur_off];

      if (pf_len == 0)
        continue;

      u_int pf_off = cur_off + sizeof(pf_len);

      /* Allocates char buffer for point formats */
      /* Each point format is a byte, so max. 3 chars will be needed */
      u_int pf_buf_len = pf_len * 3;
      pf_buf = malloc(sizeof(u_char) * pf_buf_len);
      memset(pf_buf, 0, pf_buf_len);

      /* Parse each point format */
      for (int i = 0; i < pf_len; ++i)
      {
        u_int8_t pf = payload[pf_off + i];
        snprintf(pf_buf + strlen(pf_buf), pf_buf_len - strlen(pf_buf), i == 0 ? "%d" : "-%d", pf);
      }
    }
    cur_off += ext_len;
  }

  snprintf(buf + strlen(buf), BUF_LEN - strlen(buf), type == CLIENT ? "%s," : "%s", extensions);

  /* Adds supported EC curves eventually */
  if (ec_buf != NULL)
  {
    if (type == CLIENT)
      snprintf(buf + strlen(buf), BUF_LEN - strlen(buf), "%s,", ec_buf);
    free(ec_buf);
  }
  else
  {
    if (type == CLIENT)
      snprintf(buf + strlen(buf), BUF_LEN - strlen(buf), "%c", ',');
  }
  /* Adds elliptic point formats eventually */
  if (pf_buf != NULL)
  {
    if (type == CLIENT)
      snprintf(buf + strlen(buf), BUF_LEN - strlen(buf), "%s", pf_buf);
    free(pf_buf);
  }
  else
  {
    if (type == CLIENT)
        snprintf(buf + strlen(buf), BUF_LEN - strlen(buf), "%c", ',');
  }

  return cur_off;
}

u_int16_t add_cipher(const u_char *payload, const u_int16_t PAYLOAD_LEN, char *buf, const u_int16_t BUF_LEN)
{
  /* Locate cipher */
  uint8_t sid_len = payload[OFFSET_TLS_SESSION_ID_LEN];
  u_int cipher_offset = OFFSET_TLS_SESSION_ID_LEN + sizeof(sid_len) + sid_len;

  if (cipher_offset > PAYLOAD_LEN)
  {
    /* Index to large */
    return -1;
  }
  u_int16_t cipher = payload[cipher_offset] << 8 | payload[cipher_offset + 1];

  /* Adds cipher to ja3-string */
  snprintf(buf + strlen(buf), BUF_LEN, "%d,", cipher);
  return (cipher_offset + sizeof(cipher));
}

ja3_type get_ja3_str_from_segment(const u_char *payload, uint len, char** js){
  /* Temporary buffer length for construction of ja3 string */
  const u_int16_t BUF_LEN = 5 * len;
  char buf[BUF_LEN];

  /* Adds version to ja3-string */
  int ret = add_version(payload, buf, len);

  if (ret != 0)
    return NIL;

  if (payload[0] == TLS_HANDSHAKE && payload[OFFSET_TLS_HANDSHAKE_TYPE] == TLS_SERVER_HELLO)
  {
    u_int16_t compression_offset = add_cipher(payload, len, buf, BUF_LEN);
    if (compression_offset <= 0 || compression_offset > len)
      return NIL;

    /* Get extension offset, compression suites not considered */
    u_int16_t extension_offset = get_extension_offset(payload, compression_offset);
    /* Adds extensions to ja3-string */
    u_int16_t off = add_extensions(payload, extension_offset, len, SERVER, buf, BUF_LEN);
    if (off <= 0 || off > len)
      return NIL;

    /* Sets result */
    *js = malloc(sizeof(char) * strlen(buf));
    memset(*js, 0, strlen(buf));
    strcpy(*js, buf);
    return SERVER;
  }

  /* Check type of handshake msg */
  if (payload[0] == TLS_HANDSHAKE && payload[OFFSET_TLS_HANDSHAKE_TYPE] == TLS_CLIENT_HELLO)
  {

    /* Adds cipher suites to ja3-string */
    u_int16_t compression_offset = add_cipher_suites(payload, len, buf, BUF_LEN);
    if (compression_offset <= 0 || compression_offset > len)
      return NIL;
    //printf("Comp Off: 0x%x\n", compression_offset + 0x42);

    /* Get extension offset, compression suites not considered */
    u_int16_t extension_offset = get_extension_offset(payload, compression_offset);
    if (extension_offset <= 0 || extension_offset > len)
      return NIL;
    //printf("Ext Offset: 0x%x\n", extension_offset+0x42);
    
    /* Adds extensions to ja3-string */
    u_int16_t off = add_extensions(payload, extension_offset, len, CLIENT, buf, BUF_LEN);
    if (off <= 0 || off > len)
      return NIL;
    
    /* Sets result */
    *js = malloc(sizeof(char) * strlen(buf));
    memset(*js, 0, strlen(buf));  
    strcpy(*js, buf);
    return CLIENT;
  }
  return NIL; 
}

/* Checks, a given TLS record and populates a ja3_context, if it is a TLS handshake msg*/
int get_ja3_struct_from_segment(const u_char *payload, uint payload_len, struct ja3_struct **result)
{
  /* Double check for handshake message */
  if (!payload || payload[0] != TLS_HANDSHAKE)
  {
    return 1;
  }

  u_int32_t len;

  /* Retrieves payload length, if not already set */
  if (payload_len)
    len = payload_len;
  else
    len = payload[OFFSET_TLS_RECORD_PAYLOAD_len] << 8 |
          payload[OFFSET_TLS_RECORD_PAYLOAD_len + 1];
  
  struct ja3_struct *ja3 = malloc(sizeof(struct ja3_struct));
  /* Calculates JA3 */
  ja3_type t = get_ja3_str_from_segment(payload, len, &ja3->ja3str);
  /* Returns, if no JA3 could be extracted */
  if(t == NIL || !ja3->ja3str)
    return 1;

  ja3->ja3str_len = strlen(ja3->ja3str);
  //ja3->ja3hash = malloc(sizeof(u_int8_t)*0x10); 
  /* Typecast u_char* to unsigned char* */
  MD5((unsigned char *)ja3->ja3str, ja3->ja3str_len, ja3->ja3hash);
  //ja3->ja3hash_hex = malloc(sizeof(char)*0x20); 
  md5_to_str(ja3->ja3hash, ja3->ja3hash_hex);

  /* Set result point to point to the ja3_struct */
  *result = ja3; 

  return 0;
}

/* Takes a packet and populates a pointer to the TLS part of the packet */
int get_tls_handshake_from_pkt(const struct pcap_pkthdr *pkthdr, const u_char *packet, struct tls_connection **result)
{ 
  
  /* Parses ethernet header */
  const struct ether_header *eth_hdr = (struct ether_header *)packet;
  
  /* TCP header to work on */
  const struct tcphdr *tcp_hdr = NULL;
  u_int ip_hdr_len = 0; 
  u_int ip_pl_len = 0; 

  /* Allocate char buffers for IP addresses (max */
  char ip_src[INET6_ADDRSTRLEN];
  char ip_dst[INET6_ADDRSTRLEN];

  uint16_t type = ntohs(eth_hdr->ether_type); 
  if (type == ETHERTYPE_IP)
  {
    const struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));

    /* Takes only TCP packets into account */
    if (ip_hdr->ip_p != IPPROTO_TCP)
    {
      return 1; 
    }
      ip_hdr_len = (ip_hdr->ip_hl & 0x0f) * 4; /* last 4 bits specify dword count */

      /* Extracts source and destination IP addresses */
      inet_ntop(AF_INET, &(ip_hdr->ip_src), ip_src, INET_ADDRSTRLEN);
      inet_ntop(AF_INET, &(ip_hdr->ip_dst), ip_dst, INET_ADDRSTRLEN);

      /* Gets tcp payload (segment) size */
      ip_pl_len = ntohs(ip_hdr->ip_len);

      /* Parses TCP header */
      tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
  }    

  if(type == ETHERTYPE_IPV6)
  {   
      const struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
     
      /* Take only TCP packets into account */
      if (ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_TCP)
      {
        return 1; 
      }
        /* Extracts source and destination IP addresses */
        inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), ip_src, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), ip_dst, INET6_ADDRSTRLEN);

        /* Gets tcp payload (segment) size */
        ip_pl_len = ntohs(ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen);
        
        ip_hdr_len = sizeof(struct ip6_hdr); 

        /* Parses TCP header */
        tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
  }

  if(!tcp_hdr)
  {
    return 1;
  }

  u_int p_src, p_dst;
  p_src = ntohs(tcp_hdr->source);
  p_dst = ntohs(tcp_hdr->dest);
  
    
  u_int tcp_hdr_len = tcp_hdr->th_off * 4; /* unit of dwords -> x4 */
  if (tcp_hdr_len < 20)
  {
    /* Invalid TCP header length */
    return 1;
  }

  if (ip_pl_len == 0 || ip_pl_len > pkthdr->caplen)
  {
    /* if TSO is used, ip_len is 0x0000 */
    /* only process up to caplen bytes. */
    ip_pl_len = pkthdr->caplen;
  }
  /* Computes payload size */
  u_int tcp_pl_len = ip_pl_len - (ip_hdr_len + tcp_hdr_len);

  /* at least one cipher + compression is required */
  if (tcp_pl_len < OFFSET_CIPHER_LIST + 3)
  { 
    /* printf("TLS handshake header too short: %d bytes\n", tcp_pl_len); */
    return 1;
  }
  
  /* define/compute tcp payload (segment) offset */
  u_char *tcp_pl = (u_char *)(packet + sizeof(struct ether_header) + ip_hdr_len + tcp_hdr_len);
  
  /* Checks, if a it is a TLS record sizewise */
  if (tcp_pl_len < TLS_HANDSHAKE_RECORD_SIZE)
  {
    return 1;
  }
  /* Checks, if a msg of type handshake */
  if (tcp_pl[OFFSET_TLS_RECORD_TYPE] != TLS_HANDSHAKE)
  {
    /* printf("Not a TLS handshake: 0x%02hhx\n", *tcp_pl); */
    return 1;
  }
  /* Checks TLS version in TLS header*/
  u_int16_t tls_version = tcp_pl[OFFSET_TLS_RECORD_VERSION_MAJOR] << 8 | tcp_pl[OFFSET_TLS_RECORD_VERSION_MINOR];
  if (tls_version < SSL_MIN_GOOD_VERSION || tls_version > SSL_MAX_GOOD_VERSION)
  {
    return 1;
  }

  u_int16_t tls_pl_len = tcp_pl[OFFSET_TLS_RECORD_PAYLOAD_len] << 8 | tcp_pl[OFFSET_TLS_RECORD_PAYLOAD_len + 1];
  uint tls_hs_len = tcp_pl[OFFSET_TLS_HANDSHAKE_PAYLOAD_len] << 16 |
                    tcp_pl[OFFSET_TLS_HANDSHAKE_PAYLOAD_len + 1] << 8 |
                    tcp_pl[OFFSET_TLS_HANDSHAKE_PAYLOAD_len + 2];

  /* Checks, if TLS payload lenght matches TLS handshake length to exclude false positives*/
  if ((tls_pl_len - 4) != tls_hs_len)
  {
    return 1;
  }

  /* Allocate memory for struct tls_connection*/
  *result = (struct tls_connection *)malloc(sizeof(struct tls_connection));
  
  /* Populate tls_connection */
  strcpy((*result)->ip_src, ip_src);
  strcpy((*result)->ip_dst, ip_dst);

  /* Set ports */
  (*result)->port_src = p_src;
  (*result)->port_dst = p_dst;

  /* Allocate TLS record */
  (*result)->record = malloc(sizeof(struct tls_handshake_record));
  (*result)->record->payload_len = tcp_pl_len;
  (*result)->record->payload = malloc(sizeof(u_char) * tcp_pl_len);
  (*result)->tv = pkthdr->ts;
  /* Copy whole TCP payload (=TLS record) */
  memcpy((*result)->record->payload, tcp_pl, tcp_pl_len);

  return 0;
}

/* Takes a packet and populates a ja3_context, if it is a TLS handshake msg*/
int get_ja3_context_from_pkt(const struct pcap_pkthdr *pkthdr, const u_char *packet, struct ja3_context **result)
{
  /* Check for TLS handshake packet*/
  struct tls_connection *tls_conn; 
  int ret = get_tls_handshake_from_pkt(pkthdr, packet, &tls_conn);

  /* Return, if not a TLS handshake msg */
  if (ret != 0 || !tls_conn)
  {
    return ret;
  }
    
   /* Retrieve ja3 from header */
  struct ja3_struct *ja3;
  ret = get_ja3_struct_from_segment(tls_conn->record->payload, tls_conn->record->payload_len, &ja3);

  /* Could not form ja3 */
  if (ret != 0 || !ja3)
  {
    return ret;
  }

  /* Populate ja3_context with tls_connection and ja3 */
  *result = (struct ja3_context*) malloc(sizeof (struct ja3_context)); 
  (*result)->conn = tls_conn;
  (*result)->ja3 = ja3;

  return 0;
}

ja3_type get_ja3_hexstr_from_segment(const u_char *payload, uint payload_len, char **result){
  struct ja3_struct *js = NULL;
  int ret = get_ja3_struct_from_segment(payload, payload_len, &js);
  
  if(ret != 0 || !js)
    return NIL; 
 
  /* Copies result */
  *result = malloc(sizeof(char) * JA3HEXSTR_LEN);
  memset(*result, 0, JA3HEXSTR_LEN);
  strcpy(*result, js->ja3hash_hex); 
  ja3_type t = js->t; 
  
  /* Free ja3_struct */
  free_ja3_struct(js);
  return t; 
}

ja3_type get_ja3_str_from_pkt(const struct pcap_pkthdr *pkthdr, const u_char *packet, char **result){
  /* Check for TLS handshake packet*/
  struct tls_connection *tls_conn; 

  int ret = get_tls_handshake_from_pkt(pkthdr, packet, &tls_conn);

  /* Return, if not a TLS handshake msg */
  if (ret != 0 || !tls_conn)
  {
    return NIL;
  }
      
   /* Retrieve ja3 from header */
  ja3_type t = get_ja3_str_from_segment(tls_conn->record->payload, tls_conn->record->payload_len, result);
  
  /* Cleans tls_connection */ 
  free_tls_connection(tls_conn); 

  /* Could not form ja3 */
  if (t == NIL || !result)
  {
    return NIL;
  }

  return t;
}

ja3_type get_ja3_hexstr_from_pkt(const struct pcap_pkthdr *pkthdr, const u_char *packet, char **result){
  /* Check for TLS handshake packet*/
  struct tls_connection *tls_conn; 
  int ret = get_tls_handshake_from_pkt(pkthdr, packet, &tls_conn);

  /* Return, if not a TLS handshake msg */
  if (ret != 0 || !tls_conn)
  {
    return NIL;
  }
   /* Retrieve ja3 from header */
  ja3_type t = get_ja3_hexstr_from_segment(tls_conn->record->payload, tls_conn->record->payload_len, result);
  
  /* Cleans tls_connection */ 
  free_tls_connection(tls_conn); 
  
  /* Could not form ja3 */
  if (t == NIL || !*result)
  { 
    return NIL;
  }

  return t; 
}


void free_tls_handshake_record(struct tls_handshake_record* thr){
  if(!thr){
    return;
  }
  if(thr->payload)
    free(thr->payload);
}
void free_tls_connection(struct tls_connection* tc){
  if(!tc){
    return;
  }
  if(tc->record)
    free_tls_handshake_record(tc->record);
}

void free_ja3_struct(struct ja3_struct* ja3){
  if(!ja3){
    printf("Not existing ja3 struct");
    return;
  }

  /* Free ja3 string */
  if(!ja3->ja3str)
    free(ja3->ja3str);
}

void free_ja3_context(struct ja3_context* ja3ctx){
    if(!ja3ctx){
    return;
  }
  if(ja3ctx->ja3)
    free_ja3_struct(ja3ctx->ja3);
  if(ja3ctx->conn)
    free_tls_connection(ja3ctx->conn);
}