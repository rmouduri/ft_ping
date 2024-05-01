#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>

#include "ft_ping.h"


t_ft_ping g_ft_ping = {
    .options = {
        .count = DEFAULT_COUNT,
        .interval = DEFAULT_INTERVAL,
        .linger = DEFAULT_LINGER,
        .data_packet_size = DEFAULT_DATA_PACKET_SIZE,
        .timeout = DEFAULT_TIMEOUT,
        .ttl = DEFAULT_TTL,
        .pattern = DEFAULT_PATTERN,
        .pattern_size = 0
    },
    .host_arg_name = NULL,
    .sockfd = -1,
    .address_type = NONE,

    .res = NULL,
    // .sa4,

    .packets_sent = 0,
    .packets_received = 0
};


address_type get_address_info(const char *arg) {
    struct sockaddr_in6 sa6;
    struct addrinfo hints;

    g_ft_ping.sa4.sin_family = AF_INET;
    if (inet_pton(AF_INET, arg, &g_ft_ping.sa4.sin_addr) == 1) {
        return IPV4;
    }

    if (inet_pton(AF_INET6, arg, &sa6.sin6_addr) == 1) {
        return IPV6;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP;

    if (getaddrinfo(arg, NULL, &hints, &g_ft_ping.res) == 0) {
        memset(&g_ft_ping.sa4, 0, sizeof(g_ft_ping.sa4));
        g_ft_ping.sa4.sin_family = AF_INET;
        g_ft_ping.sa4.sin_port = htons(0);
        g_ft_ping.sa4.sin_addr = ((struct sockaddr_in *)g_ft_ping.res->ai_addr)->sin_addr;
        return FQDN;
    }

    return NONE;
}


int main(int argc, char **argv) {
    get_options(argc, argv);

    if (optind == argc) {
        exit_missing_host(64);
    }
    g_ft_ping.host_arg_name = argv[optind];

    g_ft_ping.address_type = get_address_info(g_ft_ping.host_arg_name);
    if (g_ft_ping.address_type == IPV6) {
        exit_ipv6_support(2);
    } else if (g_ft_ping.address_type == NONE) {
        exit_unknown_host(2);
    }

    init_socket();

    signal(SIGINT, &exit_statistics);

    memset(g_ft_ping.seq_packets_sent, 0, USHRT_MAX / 8 + 1);

    ping_loop();

    exit_statistics(EXIT_SUCCESS);
}