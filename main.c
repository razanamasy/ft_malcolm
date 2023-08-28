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
                printf("ARP Request Received:\n");

                printf("Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                       arp_packet->sender_mac[0], arp_packet->sender_mac[1], arp_packet->sender_mac[2],
                       arp_packet->sender_mac[3], arp_packet->sender_mac[4], arp_packet->sender_mac[5]);

                printf("Sender IP: %d.%d.%d.%d\n",
                       arp_packet->sender_ip[0], arp_packet->sender_ip[1],
                       arp_packet->sender_ip[2], arp_packet->sender_ip[3]);
            }
        }
    }

    close(sockfd);

    return 0;
}

