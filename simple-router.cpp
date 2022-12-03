/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

void
SimpleRouter::handleARPRequest(const Buffer& packet, const std::string& inIface){
  std::cout << "Handling ARP request now..." << std::endl;
  ethernet_hdr * eth_request_ptr = (ethernet_hdr *)packet.data(); 
  arp_hdr * arp_request_ptr = (arp_hdr *)(packet.data() + sizeof(ethernet_hdr));

  // check ip address
  const Interface* iface = findIfaceByName(inIface);
  if (arp_request_ptr->arp_tip != iface->ip){
    std::cerr << "ARP destination is not this router, ignoring" << std::endl;
    return;
  }

  // generate reply packet
  Buffer reply(sizeof(packet));
  
  ethernet_hdr * eth_reply_ptr = (ethernet_hdr *)reply.data();
  memcpy(eth_reply_ptr->ether_shost, iface->addr, ETHER_ADDR_LEN);
  memcpy(eth_reply_ptr->ether_dhost, eth_request_ptr->ether_shost, ETHER_ADDR_LEN);
  eth_reply_ptr->ether_type = htons(ethertype_arp);
  
  arp_hdr * arp_reply_ptr = (arp_hdr *)(reply.data() + sizeof(ethernet_hdr));
  arp_reply_ptr->arp_hrd = htons(arp_hrd_ethernet);
  arp_reply_ptr->arp_pro = htons(ethertype_ip);
  arp_reply_ptr->arp_hln = 6;
  arp_reply_ptr->arp_pln = 4;
  arp_reply_ptr->arp_op = htons(arp_op_reply)
  memcpy(arp_reply_ptr->arp_sha, iface->addr, ETHER_ADDR_LEN);
  arp_reply_ptr->arp_sip = iface->ip;
  memcpy(arp_reply_ptr->arp_tha, arp_request_ptr->arp_sha, ETHER_ADDR_LEN);
  arp_reply_ptr->arp_tip = arp_request_ptr->arp_sip;

  // send reply
  sendPacket(reply, inIface);
}

void
SimpleRouter::handleARPReply(const Buffer& packet, const std::string& inIface){
  std::cout << "Handling ARP reply now..." << std::endl;
  
  arp_hdr * header_ptr = (arp_hdr *)(packet.data() + sizeof(ethernet_hdr));
  uint32_t s_ip = header_ptr->arp_sip;
  Buffer s_mac(header_ptr->arp_sha, header_ptr->arp_sha + 6);
  std::cout << "IP: " << header_ptr->arp_sip << " MAC: " << header_ptr->arp_sha << std::endl;

  // insert mac-ip to arp-cache
  if (m_arp.lookup(s_ip) == nullptr){
    auto arp_request = m_arp.insertArpEntry(s_mac, s_ip);
    // handle queued requests if exist
    if (arp_request != nullptr){
      for (auto &req : arp_request->packets){
        ethernet_hdr* ether_ptr = (ethernet_hdr *)req.packet.data();
        memcpy(ether_ptr->ether_dhost, s_mac, ETHER_ADDR_LEN);
        sendPacket(req.packet, req.iface)
      }
      m_arp.removeRequest(arp_request);
    }
  }
  else{
    std::cout << "the mac-ip exists, ignoring" << std::endl;
  }
}

void
SimpleRouter::handleARP(const Buffer& packet, const std::string& inIface){
  arp_hdr * header_ptr = (arp_hdr *)(packet.data() + sizeof(ethernet_hdr));
  std::cout << "Handling ARP packet now..." << std::endl;

  /* check validation of ARP packet */
  // check the size of packet
  if (packet.size() != sizeof(arp_hdr) + sizeof(ethernet_hdr)){
    std::cerr << "ths size of ARP packet is smaller than arp_hdr, ignoring" << std::endl;
    return;
  }
  // check hardware type
  if (ntohs(header_ptr->arp_hrd) != arp_hrd_ethernet){
    std::cerr << "the hardware type of ARP packet is not Ethernet, ignoring" << std::endl;
    return;
  }
  // check protocol type
  if (ntohs(header_ptr->arp_pro) != ethertype_ip){
    std::cerr << "the protocol type of ARP packet is not IPv4, ignoring" << std::endl;
    return;
  }

  // check hardware address length
  if (header_ptr->arp_hln != ETHER_ADDR_LEN){
    std::cerr << "the hardware address of ARP packet is not Ethernet addr's(0x06), ignoring" << std::endl;
    return;
  }
  // check protocol address length
  if (header_ptr->arp_pln != ipv4_addr_len){
    std::cerr << "the protocol address of ARP packet is not ipv4 addr's(0x04), ignoring" << std::endl;
    return;
  }
  
  /* divide by ARP type and handle */
  if (ntohs(header_ptr -> arp_op) == arp_op_request){
    std::cout << "this ARP packet is request, dispatch" << std::endl;
    handleARPRequest(packet, inIface);
  }
  else if (nthos(header_ptr -> arp_op) == arp_op_reply){
    std::cout << "this ARP packet is reply, dispatch" << std::endl;
    handleARPReply(packet, inIface);
  }
  else{
    std::cerr << "the opcode of ARP is neither request nor reply, ignoring" << std::endl;
    return;
  }
}

void
SimpleRouter::sendIcmpType3(const Buffer& packet, const std::string& inIface, uint8_t type, uint8_t code){
  ethernet_hdr * eth_ptr = (ethernet_hdr *)packet.data();
  ip_hdr * ip_ptr = (ip_hdr *)(packet.data()+sizeof(ethernet_hdr));

  Buffer reply(sizeof(ethernet_hdr)+sizeof(ip_hdr)+sizeof(icmp_t3_hdr));
  
  // fill in ICMP(type3)
  icmp_t3_hdr * reply_icmp_ptr = (icmp_t3_hdr *)(reply.data()+sizeof(ethernet_hdr)+sizeof(ip_hdr));
  reply_icmp_ptr->icmp_type = type;
  reply_icmp_ptr->icmp_code = code;
  reply_icmp_ptr->icmp_sum = 0;
  reply_icmp_ptr->next_mtu = 0;
  reply_icmp_ptr->unused = 0;
  memcpy(reply_icmp_ptr->data, ip_ptr, ICMP_DATA_SIZE);
  reply_icmp_ptr->icmp_sum = cksum(reply_icmp_ptr, sizeof(reply_icmp_ptr));
  
  // fill in ip
  const Interface* outIface = findIfaceByName(inIface);
  ip_hdr * reply_ip_ptr = (ip_hdr *)(reply.data()+sizeof(ethernet_hdr));
  memcpy(reply_ip_ptr, ip_ptr, sizeof(ip_hdr));
  reply_ip_ptr->ip_tos = 0;
  reply_ip_ptr->ip_len = htons(sizeof(ip_hdr)+sizeof(icmp_t3_hdr));
  reply_ip_ptr->ip_id  = 0;
  reply_ip_ptr->ip_tll = 64;
  reply_ip_ptr->ip_p = ip_protocol_icmp;
  reply_ip_ptr->ip_sum = 0;
  reply_ip_ptr->ip_src = outIface.ip;
  reply_ip_ptr->ip_dst = ip_ptr->ip_src;
  reply_ip_ptr->ip_sum = cksum(reply_ip_ptr, sizeof(ip_hdr));
  
  // fill in ethernet
  ethernet_hdr * reply_eth_ptr = (ethernet_hdr *)reply.data();
  memcpy(reply_eth_ptr->ether_dhost, eth_ptr->ether_shost, ETHER_ADDR_LEN);
  memcpy(reply_eth_ptr->ether_shost, eth_ptr->ether_dhost, ETHER_ADDR_LEN);
  reply_eth_ptr->type = htons(ethertype_ip);

  sendPacket(reply, inIface);
}

void
SimpleRouter::sendIcmpTimeExceeded(const Buffer& packet, const std::string& inIface){
  std::cout << "send Icmp Time Exceeded packet back..." << std::endl;
  sendIcmpType3(packet, inIface, 11, 0);
}

void
SimpleRouter::sendIcmpPortUnreachable(const Buffer& packet, const std::string& inIface){
  std::cout << "send Icmp Port Unreachable packet back..." << std::endl;
  sendIcmpType3(packet, inIface, 3, 3);
}

void
SimpleRouter::sendEchoReply(const Buffer& packet, const std::string& inIface){
  std::cout << "send Echo Reply packet..." << std::endl;
  ethernet_hdr * eth_ptr = (ethernet_hdr *)packet.data();
  ip_hdr * ip_ptr = (ip_hdr *)(packet.data()+sizeof(ethernet_hdr));
  icmp_hdr * icmp_ptr = (icmp_hdr *)(packet.data()+sizeof(ethernet_hdr)+sizeof(ip_hdr)); 
  
  Buffer reply = packet;
  // modify ethernet frames
  ethernet_hdr * reply_eth_ptr = (ethernet_hdr *)reply.data();
  memcpy(reply_eth_ptr->ether_dhost, eth_ptr->ether_shost, ETHER_ADDR_LEN);
  memcpy(reply_eth_ptr->ether_shost, eth_ptr->ether_dhost, ETHER_ADDR_LEN);
  reply_eth_ptr->ether_type = htons(ethertype_ip);
  
  // modify ipv4
  ip_hdr * reply_ip_ptr = (ip_hdr *)(reply.data()+sizeof(ethernet_hdr));
  reply_ip_ptr->ip_id = 0;
  reply_ip_ptr->ip_src = ip_ptr->ip_dst;
  reply_ip_ptr->ip_dst = ip_ptr->ip_src;
  reply_ip_ptr->ip_sum = 0;
  reply_ip_ptr->ip_ttl = 64;
  reply_ip_ptr->ip_sum = cksum(reply_ip_ptr, sizeof(ip_hdr));

  // modify icmp
  icmp_hdr * reply_icmp_ptr = (icmp_hdr *)(reply.data()+sizeof(ethernet_hdr)+sizeof(ip_hdr));
  reply_icmp_ptr->icmp_code = 0;
  reply_icmp_ptr->icmp_type = 0;
  reply_icmp_ptr->icmp_sum = 0;
  reply_icmp_ptr->icmp_sum = cksum((uint8_t*)reply_icmp_ptr, reply.size() - sizeof(ip_hdr) - sizeof(ethernet_hdr));

  sendPacket(reply, inIface);
}

void
SimpleRouter::ForwardPacket(const Buffer& packet, const std::string& inIface){
  std::cout << "Forwarding Ipv4 packet now..." << std::endl;
  ip_hdr* ip_ptr = (ip_hdr*)(packet.data()+sizeof(ethernet_hdr));

  /* look up IP/ARP in ARP cache */
  auto arp_entry = m_arp.lookup(ip_ptr->ip_dst);
  if(arp_entry == nullptr){
    std::cout << "ARP/IP not found, add queue request" << std::endl;
    m_arp.queueRequest(ip_ptr->ip_dst, packet, inIface);
    return;
  }
  /* look up IP in routing table */
  auto routing_entry = m_routingTable.lookup(ip_ptr->ip_dst);
  Interface* outIface = findIfaceByName(routing_entry.ifName);
  /* forward the packet */
  Buffer forward = packet;
  ethernet_hdr* forward_eth_ptr = (ethernet_hdr*)forward.data();
  ip_hdr* forward_ip_ptr = (ip_hdr*)(forward.data()+sizeof(ethernet_hdr));

  // modify ethernet frame
  memcpy(forward_eth_ptr->ether_shost, outIface->addr, ETHER_ADDR_LEN);
  memcpy(forward_eth_ptr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
  
  //modify ip frame
  forward_ip_ptr->ip_ttl = forward_ip_ptr->ip_ttl - 1;
  forward_ip_ptr->ip_sum = 0;
  forward_ip_ptr->ip_sum = cksum((uint8_t*)forward_ip_ptr, sizeof(ip_hdr));

  sendPacket(forward, outIface->name);
}

void
SimpleRouter::handleICMP(const Buffer& packet, const std::string& inIface){
  std::cout << "Handling ICMP packet now..." << std::endl;
  ip_hdr * ip_ptr = (ip_ptr *)(packet.data() + sizeof(ethernet_hdr));
  icmp_hdr * icmp_ptr = (icmp_hdr *)(packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
  /* check validation of ICMP packet */
  // check size of packet
  if (packet.size() < sizeof(icmp_hdr) + sizeof(ip_hdr) + sizeof(ethernet_hdr)){
    std::cerr << "the size of ICMP packet is smaller than icmp_hdr, ignoring" << std::endl;
    return;
  }
  // check checksum of ICMP
  if (cksum(icmp_ptr, packet.size() - sizeof(ip_hdr) - sizeof(ethernet_hdr)) != 0xffff) {
    std::cerr << "the checksum of ICMP packet is wrong, ignoring" << std::endl;
    return;
  }
  // check type
  if (icmp_ptr->icmp_type != 8 || icmp_ptr->icmp_code != 0){
    std::cerr << "the type of ICMP is not echo, ignoring" << std::endl;
    return;
  }

  /* send Echo Reply */
  sendEchoReply(packet, inIface);
}

void
SimpleRouter::handleIPv4(const Buffer& packet, const std::string& inIface){
  std::cout << "Handling IPv4 packet now..." << std::endl;
  ip_hdr * ip_ptr = (ip_hdr *)(packet.data()+sizeof(ethernet_hdr));

  /* check validation of IPv4 packet */
  // check size of packet
  if (packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr)){
    std::cerr << "the size of IPv4 packet is smaller than ip_hdr, ignoring" << std::endl;
    return;
  }
  // check checksum of ipv4
  if (cksum(ip_ptr, sizeof(ip_hdr)) != 0xffff) {
    std::cerr << "the checksum of IPv4 packet is wrong, ignoring" << std::endl;
    return;
  }

  /* classify datagrams by dest ip address */
  const Interface* dest_iface = findIfaceByIp(ip_ptr->ip_dst);
  if (dest_iface == nullptr){
    std::cout << "the IPv4 packet is to be forwarded" << std::endl;
    if (ip_ptr->ip_ttl == 1){
      sendIcmpTimeExceeded(packet, inIface);
    }
    else{
      ForwardPacket(packet,inIface);
    }
  }
  else{
    std::cout<< "the IPv4 packet is destined to the router"<< std::endl;
    if (ip_ptr->ip_p == ip_protocol_icmp){
      handleICMP(packet, inIface);
    }
    else if(ip_ptr->ip_p == ip_protocol_tcp || ip_ptr->ip_p == ip_protocol_udp){
      sendIcmpPortUnreachable(packet, inIface);
    }
    else{
      std::cerr << "the protocol is not matched, ignoring" << std::endl;
    }
  }
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;
  // print_hdrs(packet);

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  /* check validation of the raw Ethernet frame */

  ethernet_hdr* eth_hdr = (ethernet_hdr*)packet.data();
  // check the size of packet
  if (packet.size() < sizeof(ethernet_hdr)){
    std::cerr << "the size of packet is smaller than Ethernet header, ignoring" << std::endl;
    return;
  }
  // check destination hardware address
  
  Buffer eth_dhost(eth_hdr -> ether_dhost, eth_hdr -> ether_shost - 1);
  const Buffer BROADCAST_ADDR {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

  if (findIfaceByMac(eth_dhost)){
    std::cout << "the destination address is corresponding to mac address, accepted" << std::endl;
  }
  else if (eth_dhost == BROADCAST_ADDR){
    std::cout << "the destination address is broadcast address, accepted" << std::endl;
  }
  else{
    std::cerr << "the destination address is not destinied to the router, ignoring" << std::endl;
    return;
  }
  
  // check type of the Ethernet frame (ARP or IPv4 or others)
  uint16_t eth_type = ethertype((uint8_t *)eth_hdr);
  if (eth_type == ethertype_ip){
    std::cout << "the type of the ethernet frame is IPv4, accepted" << std::endl;
    handleIPv4(packet, inIface);
  }
  else if (eth_type == ethertype_arp){
    std::cout << "the type of the ethernet frame is ARP, accepted" << std::endl;
    handleARP(packet, inIface);
  }
  else{
    std::cerr << "the type of the Ethernet frame is neither IPv4 nor ARP, ignoring" << std::endl;
    return;
  }
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
