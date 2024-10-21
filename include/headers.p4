/*
 * Copyright 2017-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __HEADERS__
#define __HEADERS__

#include "defines.p4"

@controller_header("packet_in")
header packet_in_header_t {
    bit<9> ingress_port;
    bit<7> _padding;
}

@controller_header("packet_out")
header packet_out_header_t {
    bit<9> egress_port;
    bit<7> _padding;
}

header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}
const bit<8> ETH_HEADER_LEN = 14;

header debug_t {
  //bit<1> violation_detected;
  bit<32> data_1;
  bit<32> data_2;
  bit<32> data_3;
  bit<32> data_4;
  bit<32> data_5;
  bit<32> data_6;
  bit<32> data_7;
  bit<32> data_8;
  bit<32> data_9;
  bit<32> data_10;
  bit<32> data_11;
  bit<32> data_12;

}

header lldp_t {
    bit<7> chassis_id_tlv;
    bit<9> chassis_id_length;
    bit<8> chassis_id_subtype;
    bit<48> chassis_id;

    bit<7> port_id_tlv;
    bit<9> port_id_length;
    bit<8> port_id_subtype;
    bit<8> port_id;

    bit<7> ttl_tlv;
    bit<9> ttl_length;
    bit<16> ttl;

    bit<7> onos_disc_tlv;
    bit<9> onos_disc_length;
    bit<24> onos_disc_org_code;
    bit<8> onos_disc_subtype;
    bit<112> onos_disc;

    bit<7> onos_switch_tlv;
    bit<9> onos_switch_length;
    bit<24> onos_switch_org_code;
    bit<8> onos_switch_subtype;
    bit<104> onos_switch;

    bit<7> capabilities_tlv;
    bit<9> capabilities_length;
    bit<24> capabilities_org_code;
    bit<8> capabilities_subtype;
    bit<64> enabled_capabilities;

    bit<7> sec_tlv;
    bit<9> sec_length;
    bit<24> sec_org_code;
    bit<8> sec_subtype;
    bit<256> sec_key;

    bit<16> lldp_end;



    //bit<880> lldp_full;

}

header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    bit<16> opCode;
    bit<48> hwSrcAddr;
    bit<32> protoSrcAddr;
    bit<48> hwDstAddr;
    bit<32> protoDstAddr;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<6>  dscp;
    bit<2>  ecn;
    bit<16> len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}
const bit<8> IPV4_MIN_HEAD_LEN = 20;

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length_;
    bit<16> checksum;
}

const bit<8> UDP_HEADER_LEN = 8;

header dhcp_t {
    bit<8>    opcode;                                   // Confirmed 8 bits
    bit<8>    hardware_type;                            // Confirmed 8 bits
    bit<8>    hardware_length;                          // Confirmed 8 bits
    bit<8>    hops;                                     // Confirmed 8 bits
    bit<32>   transaction_id;                           // Confirmed 32 bits
    bit<16>   secs;                                     // Confirmed 16 bits
    bit<16>   flags;                                    // Confirmed 16 bits
    bit<32>   ciaddr; // Client IP Address              // Confirmed 32 bits
    bit<32>   yiaddr; // Your (Client) IP Address       // Confirmed 32 bits
    bit<32>   siaddr; // Next Server IP Address         // Confirmed 32 bits
    bit<32>   giaddr; // Relay Agent IP Address         // Confirmed 32 bits
    bit<48>   chaddr; // Client Hardware Address        // Confirmed 48 bits
    bit<80>   chpad;  // Client Hardware Addr Padding   // Confirmed 80 bits (10 Bytes)
    bit<512>  sname;  // Server Hostname                // Confirmed 512 bits
    bit<1024> b_file; // Boot File Name                 // Confirmed 1024 bits
    bit<32>   magic_cookie; // It's Magic
    bit<16>   msg_type_skip;
    bit<8>    message_type; // DHCP Message Type Option
    bit<456>  options; // Options from the ONOS DHCP server contain option fields of various lengths. Adds up to 60 Bytes or 480 Bits minus the message type.
}

#endif
