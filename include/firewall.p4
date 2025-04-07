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

#ifndef __FIREWALL__
#define __FIREWALL__

#include "headers.p4"
#include "defines.p4"

control firewall_control(inout headers_t hdr,
                       inout local_metadata_t local_metadata,
                       inout standard_metadata_t standard_metadata) {

    // 8 port switch

    // Port Security
    register<bit<48>>(8) port_mac_map;
    bit<48> port_known_mac;

    register<bit<32>>(8) port_ip_map;
    bit<32> port_known_ip;

    // LLDP Security
    register<bit<1>>(8) vetting_over;
    bit<1> vetting_over_val;

    // CPU Port LLDP Data
    register<bit<32>>(1) cpu_first_arrived;
    bit<32> cpu_first_arrived_value;

    register<bit<1>>(1) cpu_first_arrived_captured;
    bit<1> cpu_first_arrived_captured_value;

    register<bit<32>>(1) cpu_last_arrived;
    bit<32> cpu_last_arrived_value;

    register<bit<32>>(1) cpu_lldp_count;
    bit<32> cpu_lldp_count_value;


    // Ports LLDP Data
    register<bit<32>>(8) port_first_arrived;
    bit<32> port_first_arrived_value;

    register<bit<1>>(8) port_first_arrived_captured;
    bit<1> port_first_arrived_captured_value;

    register<bit<32>>(8) port_last_arrived;
    bit<32> port_last_arrived_value;

    register<bit<32>>(8) port_lldp_count;
    bit<32> port_lldp_count_value;


    action send_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
    }
    
    action set_egress_port(port_t port) {
        standard_metadata.egress_spec = port;
    }

    action set_next_hop_id(next_hop_id_t next_hop_id) {
        local_metadata.next_hop_id = next_hop_id;
    }
    
    action no_action() {
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action mark_as_violation(bit<1> vio) {
        local_metadata.violation = vio;
    }

    table firewall {
        key = {
            standard_metadata.ingress_port : ternary;
            hdr.ethernet.src_addr          : ternary;
            hdr.ethernet.dst_addr          : ternary;
            hdr.ethernet.ether_type        : ternary;
            hdr.ipv4.src_addr              : ternary;
            hdr.ipv4.dst_addr              : ternary;
            hdr.ipv4.protocol              : ternary;
            hdr.udp.src_port               : ternary;
            hdr.udp.dst_port               : ternary;
            local_metadata.l4_src_port     : ternary;
            local_metadata.l4_dst_port     : ternary;
        }
        actions = {
            set_egress_port;
            send_to_cpu;
            set_next_hop_id;
            no_action;
            drop;
        }
        const default_action = no_action();
    }


    apply {
      
      bit<1> violation_detected = 0;

      /*
        === Modes ===
        0x00 Multi-host Mode        No port locking. ARP header check only.
        0x01 Open Learning Mode     Port locked to host MAC and IP. Learn through ingress traffic.
        0x02 Secure Learning mode   Port locked to host MAC and IP. Learn only through DHCP offer returned from controller.
      */
      bit<8> mode = 0x02;

      //LLDP Security

      if(hdr.lldp.isValid()) {

        if(standard_metadata.ingress_port == CPU_PORT) {

            cpu_first_arrived_captured.read(cpu_first_arrived_captured_value, 0);

            if(cpu_first_arrived_captured_value == 0) {

                cpu_first_arrived_captured.write(0, 1);
                cpu_lldp_count.write(0, 0);
                //cpu_first_arrived.write(0, (bit<32>)standard_metadata.ingress_global_timestamp);

            } else {

                cpu_last_arrived.write(0, (bit<32>)standard_metadata.ingress_global_timestamp);
                cpu_lldp_count.read(cpu_lldp_count_value, 0);
                cpu_lldp_count_value = cpu_lldp_count_value + 1;
                cpu_lldp_count.write(0, cpu_lldp_count_value);
            }


          standard_metadata.egress_spec = hdr.packet_out.egress_port;
          hdr.packet_out.setInvalid();
          exit;
          //Continue

        } else {


            port_first_arrived_captured.read(port_first_arrived_captured_value, (bit<32>)standard_metadata.ingress_port);

            if(port_first_arrived_captured_value == 0) {

                port_first_arrived_captured.write((bit<32>)standard_metadata.ingress_port, 1);
                port_lldp_count.write((bit<32>)standard_metadata.ingress_port, 0);
                vetting_over.write((bit<32>)standard_metadata.ingress_port, 1);
                //port_first_arrived.write((bit<32>)standard_metadata.ingress_port, (bit<32>)standard_metadata.ingress_global_timestamp);
                cpu_lldp_count.write(0, 0);
                port_lldp_count.write(1, 0);
                port_lldp_count.write(2, 0);
                port_lldp_count.write(3, 0);

            } else {

                port_last_arrived.write((bit<32>)standard_metadata.ingress_port, (bit<32>)standard_metadata.ingress_global_timestamp);
                port_lldp_count.read(port_lldp_count_value, (bit<32>)standard_metadata.ingress_port);
                port_lldp_count_value = port_lldp_count_value + 1;
                port_lldp_count.write((bit<32>)standard_metadata.ingress_port, port_lldp_count_value);
            }

        }
      }



/*
      if (standard_metadata.ingress_port == CPU_PORT) {

        if(hdr.dhcp.isValid()) {
              if(hdr.dhcp.message_type == 0x02) {
                    // Update addresses associated with the port the DHCP request originated from
                    port_mac_map.write((bit<32>)hdr.packet_out.egress_port, hdr.dhcp.chaddr);
                    port_ip_map.write((bit<32>)hdr.packet_out.egress_port, hdr.dhcp.yiaddr);
              } else {
                    if(hdr.ethernet.src_addr == 0x0f0f0f0f0f0f) {
                                port_mac_map.write((bit<32>)hdr.packet_out.egress_port, 0);
                                port_ip_map.write((bit<32>)hdr.packet_out.egress_port, 0);
                    }
              }
        }

        standard_metadata.egress_spec = hdr.packet_out.egress_port;
        hdr.packet_out.setInvalid();
        exit;

      }
*/



      //L2 Port Security Check & Port-Mac Learning
      if(hdr.dhcp.isValid()) {
        //skip check
      } else if(hdr.ethernet.isValid()) {

            // Disable LLDP check
            vetting_over.read(vetting_over_val, (bit<32>)standard_metadata.ingress_port);
            //vetting_over_val = 0;

            if(vetting_over_val == 0) {


                port_mac_map.read(port_known_mac, (bit<32>)standard_metadata.ingress_port);
                if(port_known_mac == hdr.ethernet.src_addr) {
                  //Continue
                } else if(port_known_mac == 0) {
                  port_mac_map.write((bit<32>)standard_metadata.ingress_port, hdr.ethernet.src_addr);
                  //Continue
                } else {
                  violation_detected = 1;
                }

         //}}


              //L3 Port Security Check & Port-IP Learning

               if(hdr.ipv4.isValid()) {
                 port_ip_map.read(port_known_ip, (bit<32>)standard_metadata.ingress_port);
                 if(hdr.ipv4.src_addr == port_known_ip || hdr.ipv4.src_addr == 0x00000000) {
                   //Continue
                 } else if(port_known_ip == 0) {
                   port_ip_map.write((bit<32>)standard_metadata.ingress_port, hdr.ipv4.src_addr);
                   //Continue
                 } else {
                   violation_detected = 1;
                 }
               }

         //}}


            //ARP Verification
            if(hdr.ethernet.isValid() && hdr.arp.isValid() && violation_detected == 0) {
                  if(hdr.arp.opCode == 2) {
                    //Check HW Source
                        if(hdr.arp.hwSrcAddr != 0) {
                              if(hdr.ethernet.src_addr == hdr.arp.hwSrcAddr) {
                                    port_ip_map.read(port_known_ip, (bit<32>)standard_metadata.ingress_port);
                                    if(port_known_ip == hdr.arp.protoSrcAddr) {
                                      //Continue
                                    } else if(port_known_ip == 0) {
                                      port_ip_map.write((bit<32>)standard_metadata.ingress_port, hdr.arp.protoSrcAddr);
                                      //Continue
                                    } else {
                                      violation_detected = 1;
                                    }
                              } else {
                                violation_detected = 1;
                              }
                        }
                  }
            }


      //Check inter-arrival time
//      if(violation_detected == 0) {
//        port_packet_ival.read(last, (bit<32>)standard_metadata.ingress_port);
//        now = standard_metadata.ingress_global_timestamp;
//        ival = (bit<32>)(now - last);
//        port_packet_ival.write((bit<32>)standard_metadata.ingress_port, now);
//        if(ival < 500) {
//         violation_detected = 1; 
//        }
//      }

             //Debug message
             if(hdr.debug.isValid()) {

                   hdr.ethernet.dst_addr = hdr.ethernet.src_addr;
                   hdr.ethernet.src_addr = 0xdbdbdbdbdbdb;

                   // Remove these two lines if debugging LFA detection
                   port_ip_map.read(port_known_ip, (bit<32>)standard_metadata.ingress_port);
                   hdr.debug.data_1 = port_known_ip;

                   //cpu_first_arrived.read(cpu_first_arrived_value, 0);
                   //hdr.debug.data_1 = cpu_first_arrived_value;

                   cpu_last_arrived.read(cpu_last_arrived_value, 0);
                   hdr.debug.data_2 = cpu_last_arrived_value;

                   cpu_lldp_count.read(cpu_lldp_count_value, 0);
                   hdr.debug.data_3 = cpu_lldp_count_value;

                   // Port 1 Data
                   port_first_arrived.read(port_first_arrived_value, 1);
                   hdr.debug.data_4 = port_first_arrived_value;

                   port_last_arrived.read(port_last_arrived_value, 1);
                   hdr.debug.data_5 = port_last_arrived_value;

                   port_lldp_count.read(port_lldp_count_value, 1);
                   hdr.debug.data_6 = port_lldp_count_value;

                   // Port 2 Data
                   port_first_arrived.read(port_first_arrived_value, 2);
                   hdr.debug.data_7 = port_first_arrived_value;

                   port_last_arrived.read(port_last_arrived_value, 2);
                   hdr.debug.data_8 = port_last_arrived_value;

                   port_lldp_count.read(port_lldp_count_value, 2);
                   hdr.debug.data_9 = port_lldp_count_value;

                   // Port 3 Data
                   port_first_arrived.read(port_first_arrived_value, 3);
                   hdr.debug.data_10 = port_first_arrived_value;

                   port_last_arrived.read(port_last_arrived_value, 3);
                   hdr.debug.data_11 = port_last_arrived_value;

                   port_lldp_count.read(port_lldp_count_value, 3);
                   hdr.debug.data_12 = port_lldp_count_value;


                   standard_metadata.egress_spec = standard_metadata.ingress_port;

             }
      }



      if(violation_detected == 0) {
            firewall.apply();
      } else {
            local_metadata.violation = 1;
            hdr.packet_out.setInvalid();
            drop();
            firewall.apply();
      }
    }
}}

#endif
