/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  if (ethertype(packet) == ethertype_ip) {
    handle_ip_packet(sr, packet, len, interface)
  } else if (ethertype(packet) == ethertype_arp) {
    handle_arp_packet(sr, packet, len, interface)
  }
}/* end sr_ForwardPacket */

void handle_ip_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  // packets includes both the ip and ethernet header
  if (sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) > len) {
    fprintf("There was an error. The packet is too short.");
    return;
  }

  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  // checksum for packet
  uint16_t oldCheckSum = ip_header->ip_sum;
  ip_header->ip_sum = 0;
  uint16_t checkSum = cksum(ip_header, sizeof(sr_ip_hdr_t));

  if (checkSum != oldCheckSum) {
    fprintf("There was an error detection. The checksums for ip_header do not match");
    return;
  }
  ip_header->ip_sum = checkSum;

  // Check if we need to send this anywhere to one of our interfaces
  bool headed_to_router_interface = headed_to_interface(sr, ip_header->ip_dst);
  if (headed_to_router_interface) {
    if (ip_protocol_icmp = ip_header->ip_p) { // The packet is ICMP
        if (len < sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_hdr_t)) {
          fprintf("Cannot process ICMP packet. There was an Error. Length is too small");
          return;
        }
        sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *)(packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
        oldCheckSum = icmp_header->ip_sum;
        icmp_header->ip_sum = 0;
        checkSum = cksum(icmp_header, sizeof(sr_icmp_hdr_t));

        if(checkSum != oldCheckSum) {
          fprintf("There was an error detection. The checksums for icmp_header do not match");
          return;
        }
        icmp_header->ip_sum = checkSum;

        uint8_t type = icmp_header->icmp_type;

        // if the packet we are recieving is an Echo Request
        if (type == 8) {
          // is Echo request
          fprintf("This is a proper Echo Request");
          // send ICMP message
          send_custom_icmp_packet(sr, packet, len, interface, 0x00, 0x00, destination_interface);
        }
        else {
          fprintf("This is not a proper Echo Request. Error.");
          return;
        }
    } 
    else { //Then that means packet is not ICMP
    	
    }
  } 
  else {
    ip_header->ip_ttl--;
    // recalculate checksum
    ip_header->ip_sum = 0;
    ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

    if (ip_header->ttl == 0) {
      fprintf("Time ran out. TTL = 0. Time to die.");
      uint8_t icmp_type = 0x11;
      uint8_t icmp_code = 0x00;
      send_icmp_packet(sr, packet, len, interface, icmp_type, icmp_code);
      return;
    }

    sr_ethernet_hdr_t* e_hdr = (sr_ethernet_hdr_t*)packet;
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet+ sizeof(sr_ethernet_hdr_t));
    struct in_addr addr;
    addr.s_addr = ip_header->ip_dst;
    struct sr_rt * rt = sr_routing_table_prefix_match(sr, addr);

    if(!rt) { // if there is no match in the routing table
      fprintf("there was no match in the routing table!");
      uint8_t icmp_type = 0x03;
      uint8_t icmp_code = 0x00; 
      send_icmp_packet(sr, packet, len, interface, icmp_type, icmp_code);
      return;
    }


  }

}

void send_icmp_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */,
        uint8_t icmp_type,
        uint8_t icmp_code) {

  unsigned int hdr_len = 
      sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  uint8_t* icmp_packet = malloc(hdr_len);
  sr_ethernet_hdr_t prev_e_hdr = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t prev_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  // start adding to new header
  sr_ethernet_hdr_t new_e_hdr = (sr_ethernet_hdr_t *) icmp_packet;
  sr_ip_hdr_t new_ip_hdr = (sr_ip_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t new_icmp_t3_hdr = (sr_icmp_t3_hdr_t *)(icmp_packet + 
    sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  //CHECK ThiIS LATER
  struct in_addr addr;
  addr.s_addr = prev_ip_hdr->ip_dst;
  struct sr_rt * rt = sr_routing_table_prefix_match(sr, addr);
  if (!rt) {
    frpintf("There was an error. No Interface has been found.");
    return;
  }

  struct sr_if* new_interface = rt->routing_table;
  // fill in ethernet header
  new_e_hdr->ether_type = prev_e_hdr->ether_type;
  memcpy(new_e_hdr->ether_dhost, prev_e_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(new_e_hdr->ether_shost, new_interface->addr, ETHER_ADDR_LEN);

  new_ip_hdr->ip_hl = prev_ip_hdr->ip_hl;
  new_ip_hdr->ip_v = prev_ip_hdr->ip_v;
  new_ip_hdr->ip_tos = prev_ip_hdr->ip_tos;
  new_ip_hdr->ip_len = htons(len - sizeof(sr_ethernet_hdr_t));
  new_ip_hdr->ip_id = prev_ip_hdr->ip_id;
  new_ip_hdr->ip_off = prev_ip_hdr->ip_off;
  new_ip_hdr->ip_ttl = INIT_TTL;
  new_ip_hdr->ip_p = old_ip_hdr->ip_p;
  new_ip_hdr->ip_src = cur_interface->ip;
  new_ip_hdr->ip_dst = old_ip_hdr->ip_src;
  //have to do this after initializing everything else
  new_ip_hdr->ip_sum = 0;
  new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

  new_icmp_t3_hdr->icmp_type = icmp_type;
  new_icmp_t3_hdr->icmp_code = icmp_code;
  memcpy(new_icmp_t3_hdr->data, 
    ,ICMP_DATA_SIZE);
  new_icmp_t3_hdr->icmp_sum = 0;
  new_icmp_t3_hdr->icmp_sum = cksum(new_icmp_t3_hdr, size(sr_icmp_t3_hdr_t));

  sr_send_packet(sr, icmp_packet, hdr_len, new_interface->name);
}

struct sr_rt* sr_routing_table_prefix_match(struct sr_instance* sr, struct in_addr addr) {
  struct sr_rt* cur;
  struct sr_rt* rt = NULL;
  unsigned long length = -1;

  cur = sr->routing_table;
  while(cur) {
  
    if((cur->dest.s_addr & cur->mask.s_addr)== //Subnet Num
      (addr.s_addr & cur->mask.s_addr)){ //Subnet Mask & ip_dst
      //if there is a match with an entry in the routing table
      if(length < cur->mask.s_addr){
        length = cur->mask.s_addr;
        rt = cur;
      }
    }
    cur=cur->next;
  }
  return rt;
}

bool headed_to_interface(struct sr_instance * sr, uint32_t ip_destination)
{
  struct sr_if *currInterface = sr->if_list;
  while (currInterface) 
  {
    if(ip_destination = currInterface->ip)
    {
      return true;
    }
    currInterface = currInterface->next;
  }
  return false;
}

void handle_arp_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{

}



