/* 
    Copyright 2010 Domas Mituzas, Facebook

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/


#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>

void
handle_packet (u_char * args, const struct pcap_pkthdr *header,
	       const u_char * packet)
{

  struct tcphdr *tcp = NULL;
  struct iphdr *ip = NULL;
  struct ip6_hdr *ip6 = NULL;


  u_char *payload;
  int payload_size;
  int mysql_header, ppos;

  const u_char *p = packet;

  struct ether_header *eh = (struct ether_header *) p;
  p += sizeof (*eh);

  switch (ntohs (eh->ether_type))
    {
    case ETHERTYPE_IP:
      ip = (struct iphdr *) p;
      p += ip->ihl * 4;

      tcp = (struct tcphdr *) p;
      p += tcp->doff * 4;

      payload = (u_char *) p;
      payload_size = ntohs (ip->tot_len) - (payload - (u_char *) ip);
      break;
    case ETHERTYPE_IPV6:
      ip6 = (struct ip6_hdr *) p;
      p += sizeof (*ip6);

      tcp = (struct tcphdr *) p;
      p += tcp->doff * 4;

      payload = (u_char *) p;
      payload_size = ntohs (ip6->ip6_plen) - (payload - (u_char *) tcp);
      break;
    }

  /* No payload or not an error */
  if (payload_size < 10 || (u_char) payload[4] != 255 || payload_size > 600)
    return;

  /* This actually tries to ensure this _is_ error packet, though not firmly :-) */
  mysql_header = (int) payload[0];
  if (mysql_header + 4 != payload_size)
    return;

  ppos = payload[7] == '#' ? 13 : 7;

  char s[INET6_ADDRSTRLEN];
  if (ip6)
    inet_ntop (AF_INET6, &ip6->ip6_dst, s, sizeof (s));
  else if (ip)
    inet_ntop (AF_INET, &ip->daddr, s, sizeof (s));

  printf ("%s: %.*s\n", s, payload_size - ppos, payload + ppos);
}

int
main (int argc, char *argv[])
{
  char *dev, errbuf[PCAP_ERRBUF_SIZE];
  char filter[] = "tcp src portrange 3300-3350";
  struct bpf_program fp;

  dev = pcap_lookupdev (errbuf);
  if (dev == NULL)
    {
      fprintf (stderr, "Couldn't find default device: %s\n", errbuf);
      return (2);
    }

  pcap_t *handle = pcap_open_live (dev, BUFSIZ, 0, 1000, errbuf);
  if (!handle)
    {
      fprintf (stderr, "Could not open device %s: %s\n", dev, errbuf);
    }

  if (pcap_compile (handle, &fp, filter, 0, 0) == -1)
    {
      fprintf (stderr, "Could not parse filter %s: %s\n", filter,
	       pcap_geterr (handle));
      return (2);
    }


  if (pcap_setfilter (handle, &fp) == -1)
    {
      fprintf (stderr, "Couldn't install filter %s: %s\n", filter,
	       pcap_geterr (handle));
      return (2);
    }

  pcap_loop (handle, -1, handle_packet, NULL);

  return (0);
}
