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

#ifndef JA3_H
#define JA3_H

#include <stdlib.h>
//#include <stdint.h>

/* Network specific headers */
#include <arpa/inet.h>
#include <pcap.h>

/* 16 bytes length of hashes ja3 string equals 32 characters hex representation */
#define JA3HASH_LEN 0x10

#define JA3HEXSTR_LEN 0x21

/* Define type of JA3*/
typedef enum ja3_type{SERVER, CLIENT, NIL} ja3_type;

/* TLS record */
struct tls_handshake_record {
  /* Pointer to TCP payload data of type TLS record */
  u_char* payload;
  /* Total length of the record*/
  u_int32_t payload_len;
};

/* Information on connection */
struct tls_connection{
  /* Source IP address */
  char ip_src[INET6_ADDRSTRLEN];
  /* Destination IP address */
  char ip_dst[INET6_ADDRSTRLEN];
  /* Timestamp of packet */
  struct timeval tv;
  /* Source port */
  u_int16_t port_src;
  /* Destination port */
  u_int16_t port_dst;
  /* TLS record */
  struct tls_handshake_record* record;
};

struct ja3_struct {
  /* Server (ja3s) or client (ja3) */
  enum ja3_type t;
  /* JA3 string */
  char *ja3str;
  /* Length of ja3str */
  u_int16_t ja3str_len;
  /* JA3(S) hash, MD5 ja3-string as bytes */
  u_int8_t ja3hash[JA3HASH_LEN];
  /* JA3 hash as hex string (32 chars + \0*/
  char ja3hexstr[JA3HEXSTR_LEN];
};

struct ja3_context {
  /* Information on connection information */
  struct tls_connection *conn;
  /* JA3 hash */
  struct ja3_struct *ja3;
};

/* Takes a packet and returns a JA3 hex-string, if it is a TLS handshake msg
 *
 * Convenience method for cases, where only JA3 hexadecimal string is of interest 
 * and connection info and the like is not needed.
 */
ja3_type get_ja3_hexstr_from_pkt(const struct pcap_pkthdr *pkthdr, const u_char *packet, char **result);

/* Takes a packet and returns a human-readable JA3-string, if it is a TLS handshake msg
 *
 * Convenience method for cases, where only the human-readable JA3 string is of interest 
 * and connection info and the like is not needed.
 */
ja3_type get_ja3_str_from_pkt(const struct pcap_pkthdr *pkthdr, const u_char *packet, char **result);

/* Checks, a given TCP segment for the presence of TLS handshake data and calculates 
 * JA3 hex-string, if it is a TLS handshake msg
 *
 * Convenience method for cases, where only JA3 hexadecimal string is of interest 
 * and connection info and the like is not needed.
 */
ja3_type get_ja3_hexstr_from_segment(const u_char *payload, uint payload_len, char **result);

/* Checks, a given TCP segment for the presence of TLS handshake data and calculates 
 * human-readable JA3string, if it is a TLS handshake msg
 *
 * Convenience method for cases, where only the human-readable JA3 string is of interest 
 * and connection info and the like is not needed.
 */
ja3_type get_ja3_str_from_segment(const u_char *payload, uint payload_len, char **result);

/* Takes a packet and populates a ja3_context, if it is a TLS handshake msg */
int get_ja3_context_from_pkt(const struct pcap_pkthdr *pkthdr, const u_char *packet, struct ja3_context **result);

/* Checks, a given TLS record and populates a ja3_context, if it is a TLS handshake msg*/
int get_ja3_struct_from_segment(const u_char *payload, uint payload_len, struct ja3_struct **result);

/* Takes a packet and populates a pointer to the TLS part of the packet */
int get_tls_handshake_from_pkt(const struct pcap_pkthdr *pkthdr, const u_char *packet, struct tls_connection **result);

/* Cleans up ja3ctx */
void free_ja3_context(struct ja3_context *ja3ctx);

/* Cleans up ja3struct */
void free_ja3_struct(struct ja3_struct *ja3);

/* Cleans up tls_connection struct */
void free_tls_connection(struct tls_connection *tc);

/* Cleans up tls_handshake_record struct */
void free_tls_handshake_record(struct tls_handshake_record *thr);

#endif /* !JA3_H */
