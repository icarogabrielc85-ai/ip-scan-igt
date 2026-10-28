#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>

static volatile int g_running = 1;

static void sig_handler(int sig) {
    (void)sig;
    g_running = 0;
}

int main(int argc, char *argv[]) {
    char *interface = NULL;
    int timeout_sec = 35;

    if (argc >= 2) {
        interface = argv[1];
    }
    if (argc >= 3) {
        timeout_sec = atoi(argv[2]);
        if (timeout_sec <= 0) timeout_sec = 30;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        fprintf(stderr, "ERROR_PERMISSION: %s\n", strerror(errno));
        return 1;
    }

    if (interface && strlen(interface) > 0) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name) - 1);
        if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
            fprintf(stderr, "ERROR_INTERFACE: %s\n", strerror(errno));
            close(sock);
            return 3;
        }

        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifr.ifr_ifindex;
        sll.sll_protocol = htons(ETH_P_ALL);

        if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            fprintf(stderr, "ERROR_BIND: %s\n", strerror(errno));
            close(sock);
            return 4;
        }
    }

    // Set 1-second receive timeout on socket for loop responsiveness
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));

    fprintf(stderr, "SNIFFING_START: Interface=%s, Timeout=%ds\n", interface ? interface : "any", timeout_sec);

    time_t start_time = time(NULL);
    unsigned char buffer[4096];

    while (g_running) {
        time_t now = time(NULL);
        if (now - start_time >= timeout_sec) {
            fprintf(stderr, "TIMEOUT: No LLDP/CDP frames received within %d seconds\n", timeout_sec);
            close(sock);
            return 2;
        }

        ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                continue;
            }
            fprintf(stderr, "ERROR_RECV: %s\n", strerror(errno));
            close(sock);
            return 5;
        }

        if (len < 14) continue; // Minimum Ethernet header

        // Ethernet Destination MAC
        // LLDP Multicast MACs: 01:80:C2:00:00:0E, 01:80:C2:00:00:03, 01:80:C2:00:00:00
        // Cisco CDP Multicast MAC: 01:00:0C:CC:CC:CC
        int is_lldp_mac = (buffer[0] == 0x01 && buffer[1] == 0x80 && buffer[2] == 0xc2 &&
                           buffer[3] == 0x00 && buffer[4] == 0x00 &&
                           (buffer[5] == 0x0e || buffer[5] == 0x03 || buffer[5] == 0x00));

        int is_cdp_mac = (buffer[0] == 0x01 && buffer[1] == 0x00 && buffer[2] == 0x0c &&
                          buffer[3] == 0xcc && buffer[4] == 0xcc && buffer[5] == 0xcc);

        uint16_t ethertype = (buffer[12] << 8) | buffer[13];
        int is_lldp_ethertype = (ethertype == 0x88CC);

        if (is_lldp_ethertype || is_lldp_mac || is_cdp_mac) {
            // Found a matching frame! Print raw hex to stdout
            printf("FRAME:");
            for (ssize_t i = 0; i < len; i++) {
                printf("%02x", buffer[i]);
            }
            printf("\n");
            fflush(stdout);

            close(sock);
            return 0; // Success!
        }
    }

    close(sock);
    return 2;
}
