#include "ft_ping.h"
#include "control_messages.h"

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>


static unsigned short hdr_checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

static void fill_data_pattern(void) {
    ssize_t di = sizeof(struct iphdr) + sizeof(struct icmphdr) + (g_ft_ping.options.data_packet_size >= sizeof(struct timeval) ? sizeof(struct timeval) : 0);

    if (g_ft_ping.options.pattern && g_ft_ping.options.pattern_size) {
        for (ssize_t pi = 0; di < (ssize_t)(g_ft_ping.options.data_packet_size + sizeof(struct iphdr) + sizeof(struct icmphdr)); ++di) {
            if (pi >= g_ft_ping.options.pattern_size) {
                pi = 0;
            }
            g_ft_ping.packet[di] = g_ft_ping.options.pattern[pi++];
        }
    } else {
        unsigned char uc = 0;

        for (; di < (ssize_t)(g_ft_ping.options.data_packet_size + sizeof(struct iphdr) + sizeof(struct icmphdr)); ++di) {
            g_ft_ping.packet[di] = uc++;
        }
    }
}

static void fill_data_timestamp(void) {
    struct timeval  *tv_data_time = (struct timeval *)(g_ft_ping.packet + sizeof(struct iphdr) + sizeof(struct icmphdr));

    if (g_ft_ping.options.data_packet_size < sizeof(struct timeval)) {
        return ;
    }

    if (gettimeofday(tv_data_time, NULL) != 0) {
        fprintf(stderr, "%s: gettimeofday: %s\n", PROG_NAME, strerror(errno));
        exit_ping(EXIT_FAILURE);
    }
}

static void fill_base_icmp_header(void) {
    struct icmphdr  *icmp_hdr = (struct icmphdr *)(g_ft_ping.packet + sizeof(struct iphdr));

    icmp_hdr->type = ICMP_ECHO;
    icmp_hdr->code = 0;
    icmp_hdr->un.echo.id = htons(getpid());
}

static uint16_t generate_ip_id(void) {
    static uint16_t id = 0;
    struct timeval  tv;

    gettimeofday(&tv, NULL);

    return (tv.tv_usec & 0xFFFF) | (id++ << 16);
}

static void fill_base_ip_header(void) {
    struct iphdr  *ip_hdr = (struct iphdr *)g_ft_ping.packet;

    ip_hdr->ihl = 5;
    ip_hdr->version = 4;
    ip_hdr->tos = 0;
    ip_hdr->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + g_ft_ping.options.data_packet_size;
    ip_hdr->frag_off |= htons(0x4000);
    ip_hdr->ttl = g_ft_ping.options.ttl;
    ip_hdr->protocol = IPPROTO_ICMP;
    ip_hdr->saddr = INADDR_ANY;
    ip_hdr->daddr = g_ft_ping.sa4.sin_addr.s_addr;
}

static void fill_rest_icmp_header(void) {
    struct icmphdr *icmp_hdr = (struct icmphdr *)(g_ft_ping.packet + sizeof(struct iphdr));

    icmp_hdr->un.echo.sequence = htons(g_ft_ping.packets_sent);

    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = hdr_checksum(icmp_hdr, sizeof(struct icmphdr) + g_ft_ping.options.data_packet_size);
}

static void fill_rest_ip_header(void) {
    struct iphdr *ip_hdr = (struct iphdr *)g_ft_ping.packet;

    ip_hdr->id = generate_ip_id();

    ip_hdr->check = 0;
    ip_hdr->check = hdr_checksum(ip_hdr, sizeof(struct iphdr) + sizeof(struct icmphdr) + g_ft_ping.options.data_packet_size);
}

static void print_advanced_response(const struct iphdr *ip_reply, const struct icmphdr *icmp_reply, const uint8_t is_dupe) {
    struct timeval  *start, diff, end;
    char            recv_time[64], *needle;

    if (g_ft_ping.options.data_packet_size >= sizeof(struct timeval)) {
        start = (struct timeval *)&(g_ft_ping.buffer[ip_reply->ihl * 4 + sizeof(struct icmphdr)]);

        gettimeofday(&end, NULL);
        diff.tv_sec = end.tv_sec - start->tv_sec;
        diff.tv_usec = end.tv_usec - start->tv_usec;
        if (diff.tv_usec < 0) {
            diff.tv_sec--;
            diff.tv_usec += 1000000;
        }
        sprintf(recv_time, "%ld.%ld", diff.tv_usec / 1000, diff.tv_usec - (diff.tv_usec / 1000));
        needle = strstr(recv_time, ".");
        for (int i = 1; i < 4; ++i) {
            if (*(needle + i) == 0) {
                needle[i] = '0';
            }
        }
        needle[4] = 0;

        printf("icmp_seq=%u ttl=%d time=%s ms%s\n", ntohs(icmp_reply->un.echo.sequence), ip_reply->ttl, recv_time, (is_dupe ? PING_DUPE_ERROR : ""));
    } else {
        printf("icmp_seq=%u, ttl=%d%s\n", ntohs(icmp_reply->un.echo.sequence), ip_reply->ttl, (is_dupe ? PING_DUPE_ERROR : ""));
    }
}

static void print_error_response(const struct iphdr *ip_reply, const struct icmphdr *icmp_reply) {
    static const char   codes[19][14][68] = ICMP_ERROR_CODES;

    printf("%s\n", codes[icmp_reply->type][icmp_reply->code]);

    if (g_ft_ping.options.flags & VERBOSE) {
        struct iphdr    *error_iphdr = (struct iphdr *)(g_ft_ping.buffer + (ip_reply->ihl * 4) + sizeof(struct icmphdr));
        struct icmphdr  *error_icmphdr = (struct icmphdr *)(g_ft_ping.buffer + (ip_reply->ihl * 4) + sizeof(struct icmphdr) + (error_iphdr->ihl * 4));
        uint8_t         *hex_error_iphdr = (uint8_t *)error_iphdr;
        char            ip_str[INET_ADDRSTRLEN];

        printf("IP Hdr Dump:\n");

        for (size_t i = 0; i < sizeof(struct iphdr); i += 2) {
            printf(" %02x%02x", *(hex_error_iphdr), *(hex_error_iphdr + 1));
            hex_error_iphdr += 2;
        }

        printf("\nVr HL TOS  Len   ID Flg  off TTL Pro  cks      Src\tDst\tData\n");
        printf(" %x  %x  %02x %04x %04x   %x %04x  %02x  %02x %04x ",
            error_iphdr->version, error_iphdr->ihl, error_iphdr->tos, htons(error_iphdr->tot_len),
            htons(error_iphdr->id), htons(error_iphdr->frag_off) >> 13,
            htons(error_iphdr->frag_off) & 0x1FFF, error_iphdr->ttl, error_iphdr->protocol,
            htons(error_iphdr->check));
        inet_ntop(AF_INET, &error_iphdr->saddr, ip_str, sizeof(ip_str));
        printf("%s  ", ip_str);
        inet_ntop(AF_INET, &error_iphdr->daddr, ip_str, sizeof(ip_str));
        printf("%s\n", ip_str);

        printf("ICMP: type %x, code %x, size %lu, id 0x%04x, seq 0x%04x\n",
            error_icmphdr->type, error_icmphdr->code,
            sizeof(struct icmphdr) + g_ft_ping.options.data_packet_size, htons(error_icmphdr->un.echo.id), htons(error_icmphdr->un.echo.sequence));
    }
}

static void print_base_response(const ssize_t recv_len, const struct iphdr *ip_reply) {
    printf("%lu bytes from %s: ", recv_len - sizeof(struct iphdr), inet_ntoa(*(struct in_addr *)&ip_reply->saddr));
}

static void receive_packet(void) {
    struct iphdr    *ip_reply;
    struct icmphdr  *icmp_reply;
    uint16_t        curr_seq;
    uint8_t         is_dupe = 0;

    // Receive packet
    if (g_ft_ping.packets_sent > g_ft_ping.packets_received) {
        ssize_t recv_len = recvfrom(g_ft_ping.sockfd, g_ft_ping.buffer, sizeof(g_ft_ping.buffer), 0, NULL, NULL);
        
        if (recv_len < 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) {
            fprintf(stderr, "%s: recvfrom: %s\n", PROG_NAME, strerror(errno));
            exit_ping(EXIT_FAILURE);
        }

        if (recv_len >= 0) {
            ip_reply = (struct iphdr *)g_ft_ping.buffer;
            icmp_reply = (struct icmphdr *)&(g_ft_ping.buffer[ip_reply->ihl * 4]);

            if (icmp_reply->type == ICMP_ECHOREPLY) {
                if (icmp_reply->un.echo.id != htons(getpid())) {
                    return ;
                }
                print_base_response(recv_len, ip_reply);

                curr_seq = htons(icmp_reply->un.echo.sequence);
                if (g_ft_ping.seq_packets_sent[curr_seq / 8] & (uint8_t)1 << (curr_seq % 8)) {
                    g_ft_ping.seq_packets_sent[curr_seq / 8] &= ~(1 << (curr_seq % 8));
                    g_ft_ping.packets_received++;
                } else {
                    is_dupe = 1;
                }
                print_advanced_response(ip_reply, icmp_reply, is_dupe);
            } else if (icmp_reply->type != ICMP_ECHO) {
                print_base_response(recv_len, ip_reply);
                print_error_response(ip_reply, icmp_reply);
            }
        }
    }
}

void print_statistics(void) {
    printf("--- %s ping statistics ---\n" \
           "%lu packets transmitted, %lu packets received, %d%% packet loss\n",
        g_ft_ping.host_arg_name, g_ft_ping.packets_sent, g_ft_ping.packets_received, \
            (int)(100 - ((float)g_ft_ping.packets_received / (float)g_ft_ping.packets_sent * 100))
    );
}

void init_socket(void) {
    if ((g_ft_ping.sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        fprintf(stderr, "%s: socket: %s\n", PROG_NAME, strerror(errno));
        exit_ping(EXIT_FAILURE);
    }

    struct timeval tv_sock_timeout;
    tv_sock_timeout.tv_sec = 0;
    tv_sock_timeout.tv_usec = 100000; // 0.1s
    if (setsockopt(g_ft_ping.sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv_sock_timeout, sizeof(tv_sock_timeout)) < 0) {
        fprintf(stderr, "%s: setsockopt: %s\n", PROG_NAME, strerror(errno));
        exit_ping(EXIT_FAILURE);
    }

    int flag = 1;
    if (setsockopt(g_ft_ping.sockfd, IPPROTO_IP, IP_HDRINCL, &flag, sizeof(flag)) < 0) {
        fprintf(stderr, "%s: setsockopt: %s\n", PROG_NAME, strerror(errno));
        exit_ping(EXIT_FAILURE);
    }
}

time_t timeval_diff_seconds(const struct timeval *tv_start) {
    struct timeval  tv_end, tv_diff;

    gettimeofday(&tv_end, NULL);

    tv_diff.tv_sec = tv_end.tv_sec - tv_start->tv_sec;
    tv_diff.tv_usec = tv_end.tv_usec - tv_start->tv_usec;
    if (tv_diff.tv_usec < 0) {
        tv_diff.tv_sec--;
        tv_diff.tv_usec += 1000000;
    }

    return tv_diff.tv_sec;
}

void ping_loop(void) {
    struct timeval  tv_ping_start = {0, 0}, tv_last_sent = {0, 0};
    uint16_t        curr_seq;
    char            ip_str[INET_ADDRSTRLEN];
    char            id_verbose[24] = "";

    fill_base_ip_header();
    fill_base_icmp_header();
    fill_data_pattern();

    inet_ntop(AF_INET, &g_ft_ping.sa4.sin_addr, ip_str, sizeof(ip_str));

    if (g_ft_ping.options.flags & VERBOSE) {
        uint16_t id = htons(((struct icmphdr *)(g_ft_ping.packet + sizeof(struct iphdr)))->un.echo.id);

        sprintf(id_verbose, ", id 0x%x = %d", id, id);
    }
    printf("PING %s (%s): %d data bytes%s\n", g_ft_ping.host_arg_name, ip_str, g_ft_ping.options.data_packet_size, id_verbose);


    while (1) {
        receive_packet();

        // Send packet
        if ((g_ft_ping.options.count == 0 || g_ft_ping.packets_sent < g_ft_ping.options.count) && \
                timeval_diff_seconds(&tv_last_sent) >= g_ft_ping.options.interval) {

            gettimeofday(&tv_last_sent, NULL);

            fill_data_timestamp();
            fill_rest_icmp_header();
            fill_rest_ip_header();

            ssize_t bytes_sent = sendto(g_ft_ping.sockfd, g_ft_ping.packet,
                sizeof(struct iphdr) + sizeof(struct icmphdr) + g_ft_ping.options.data_packet_size,
                0, (struct sockaddr *)&g_ft_ping.sa4, sizeof(g_ft_ping.sa4));

            if (!tv_ping_start.tv_sec && !tv_ping_start.tv_usec) {
                gettimeofday(&tv_ping_start, NULL);
            }

            if (bytes_sent < 0) {
                fprintf(stderr, "%s: sendto: (%d) %s\n", PROG_NAME, errno, strerror(errno));
                exit_ping(EXIT_FAILURE);
            }

            curr_seq = htons(((struct icmphdr *)(g_ft_ping.packet + sizeof(struct iphdr)))->un.echo.sequence);
            g_ft_ping.seq_packets_sent[curr_seq / 8] |= (1 << (curr_seq % 8));
            g_ft_ping.packets_sent++;
        }

        if ((g_ft_ping.options.flags & TIMEOUT && timeval_diff_seconds(&tv_ping_start) >= g_ft_ping.options.timeout) || \
                (g_ft_ping.options.count > 0 && g_ft_ping.packets_sent == g_ft_ping.options.count && \
                (g_ft_ping.packets_sent == g_ft_ping.packets_received || timeval_diff_seconds(&tv_last_sent) >= g_ft_ping.options.linger))) {
            break;
        }
    }
}