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
#include <openssl/md5.h>
#include <pcap.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include "ja3.h"

void handle_packet_cb(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet){
  char* ja3str = NULL; 
  ja3_type type = get_ja3_str_from_pkt(pkthdr, packet, &ja3str);
  
  if(type != NIL && ja3str){
    printf("%s\t", type == CLIENT ? "ja3" : "ja3s");
    printf("%s\t", ja3str);
    free(ja3str); 
    
  }   
  
  char* ja3hexstr; 
  type = get_ja3_hexstr_from_pkt(pkthdr, packet, &ja3hexstr);

  if(type != NIL && ja3hexstr){
    printf("%s\n", ja3hexstr);
    free(ja3hexstr); 
  }   
  struct ja3_context *jc = NULL;
  int i = get_ja3_context_from_pkt(pkthdr, packet, &jc);

  if(i == 0 && jc){
    printf("%ld\n", jc->conn->tv.tv_sec);
    free(jc); 
  }   
}

int main(int argc, char** argv)
{
  /* Check argument count */
  if(argc != 2)
  {
    printf("usage: %s <file>\n", argv[0]);
    return EXIT_FAILURE;
  }

  /* Read pcap-file */
  char errbuf[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */
  pcap_t *fp = pcap_open_offline(argv[1], errbuf);

  if(fp == NULL)
  {
    fprintf(stderr, "\npcap_open_offline() failed: %s\n", errbuf);
    return EXIT_FAILURE;
  }

  /* Extract all TLS hello packets */
  if (pcap_loop(fp, 0, handle_packet_cb, NULL) < 0) {
    fprintf(stderr, "\npcap_loop() failed: %s\n", pcap_geterr(fp));
    return EXIT_FAILURE;
  }
  /* Close pcap-file */
  pcap_close(fp);

  return EXIT_SUCCESS;
}
