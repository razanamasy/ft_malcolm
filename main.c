#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#define ETHER_TYPE_ARP 0x0806
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define BUF_SIZE 1024

struct arp_header {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_len;
    uint8_t protocol_len;
    uint16_t operation;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};

int main() {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

    if (sockfd == -1) {
        perror("socket");
        return 1;
    }

    printf("Listening for ARP requests...\n");

    while (1) {
        unsigned char buffer[BUF_SIZE];
        ssize_t recv_size = recv(sockfd, buffer, sizeof(buffer), 0);

        if (recv_size < 42) {
            fprintf(stderr, "Received incomplete ARP packet\n");
            continue;
        }

        struct ethhdr* eth_header = (struct ethhdr*)buffer;

        if (ntohs(eth_header->h_proto) == ETHER_TYPE_ARP) {
            struct arp_header* arp_packet = (struct arp_header*)(buffer + sizeof(struct ethhdr));

            if (ntohs(arp_packet->operation) == ARP_REQUEST) {

		//HERE We are just detecting the ARP request from the good addresse
                struct in_addr sender_ip;
                memcpy(&sender_ip, arp_packet->sender_ip, sizeof(struct in_addr));

                char sender_ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &sender_ip, sender_ip_str, INET_ADDRSTRLEN);

                printf("ARP Request Received from >%s<\n", sender_ip_str);

		//IF IT Comes from the TARGET address then show it and respond
                if (strcmp(sender_ip_str, "192.168.56.111") == 0) {
                    printf("TARGET SPOTTED !");
                    printf("TARGET MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
                       arp_packet->sender_mac[0], arp_packet->sender_mac[1], arp_packet->sender_mac[2],
                       arp_packet->sender_mac[3], arp_packet->sender_mac[4], arp_packet->sender_mac[5]);

		    printf("TARGET IP: %s\n",sender_ip_str);



	/*	// Construct an ARP reply packet to respond
               	    struct ethhdr reply_eth_header;
                    struct arp_header reply_arp_packet;

                // Fill in Ethernet header
                    memcpy(reply_eth_header.h_dest, eth_header->h_source, 6);
                // Fill in your MAC address as the sender
                // Set the Ethernet frame type to ARP
                    reply_eth_header.h_proto = htons(ETHER_TYPE_ARP);

                // Fill in ARP header
                    reply_arp_packet.hardware_type = htons(ARPHRD_ETHER);
                    reply_arp_packet.protocol_type = htons(ETH_P_IP);
                    reply_arp_packet.hardware_len = 6;
                    reply_arp_packet.protocol_len = 4;
                    reply_arp_packet.operation = htons(ARP_REPLY);
                    memcpy(reply_arp_packet.sender_mac, eth_header->h_dest, 6); // Your MAC
                    memcpy(reply_arp_packet.sender_ip, arp_packet->target_ip, 4); // Your IP
                    memcpy(reply_arp_packet.target_mac, arp_packet->sender_mac, 6);
                    memcpy(reply_arp_packet.target_ip, arp_packet->sender_ip, 4);

                // Construct the reply packet
                    char reply_packet[42];
                    memcpy(reply_packet, &reply_eth_header, sizeof(struct ethhdr));
                    memcpy(reply_packet + sizeof(struct ethhdr), &reply_arp_packet, sizeof(struct arp_header));

                // Send the ARP reply
                    ssize_t send_size = send(sockfd, reply_packet, sizeof(reply_packet), 0);
                    if (send_size == -1) {
                        perror("send");
                    } else {
                        printf("Sent ARP reply\n");
                    }
*/


		}

            }
        }
    }

    close(sockfd);
    return 0;
}


