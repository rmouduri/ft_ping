#include "ft_ping.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>


// print functions
static void printerr_missing_host(void) {
    fprintf(stderr, "%s\n", PING_MISSING_HOST);
}

static void printerr_ping_error_usage(void) {
    fprintf(stderr, "%s\n", PING_ERROR_USAGE);
}

static void print_ping_help(void) {
    printf("%s\n", PING_HELP);
}

static void print_ping_usage(void) {
    printf("%s\n", PING_USAGE);
}

static void printerr_ipv6_not_supported(void) {
    fprintf(stderr, "%s\n", PING_IPV6_SUPPORT);
}

static void printerr_unknown_host(void) {
    fprintf(stderr, "%s\n", PING_UNKNOWN_HOST);
}


// exit functions
void exit_ping(int ret) {
    if (g_ft_ping.options.pattern) {
        free(g_ft_ping.options.pattern);
    }

    if (g_ft_ping.res) {
        freeaddrinfo(g_ft_ping.res);
    }

    if (g_ft_ping.sockfd >= 0) {
        close(g_ft_ping.sockfd);
    }

    exit(ret);
}

void exit_missing_host(int ret) {
    printerr_missing_host();
    printerr_ping_error_usage();
    exit_ping(ret);
}

void exit_error_usage(int ret) {
    printerr_ping_error_usage();
    exit_ping(ret);
}

void exit_help(int ret) {
    print_ping_help();
    exit_ping(ret);
}

void exit_usage(int ret) {
    print_ping_usage();
    exit_ping(ret);
}

void exit_statistics(int ret) {
    (void)ret;
    print_statistics();
    exit_ping(EXIT_SUCCESS);
}

void exit_ipv6_support(int ret) {
    printerr_ipv6_not_supported();
    exit_ping(ret);
}

void exit_unknown_host(int ret) {
    printerr_unknown_host();
    exit_ping(ret);
}