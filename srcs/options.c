#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "ft_ping.h"


unsigned char *hex_to_value_string(const char *hex_string, ssize_t len) {
    unsigned char *ret = (unsigned char *)malloc((len % 2 == 0 ? len : len + 1) / 2 + 1);

    if (ret == NULL) {
        fprintf(stderr, "%s: malloc error in hex_to_value_string()\n", PROG_NAME);
        exit_ping(EXIT_FAILURE);
    }

    int i, j = 0;
    for (i = 0; i < len; i += 2) {
        unsigned char value = 0;
        int k = 0;

        for (; k < 2; k++) {
            char c = hex_string[i + k];
            if (c >= '0' && c <= '9') {
                value = value * 16 + (c - '0');
            } else if (c >= 'a' && c <= 'f') {
                value = value * 16 + (c - 'a' + 10);
            } else if (c >= 'A' && c <= 'F') {
                value = value * 16 + (c - 'A' + 10);
            } else if (c) {
                fprintf(stderr, "%s: error in pattern near %s\n", PROG_NAME, &hex_string[i + k]);
                free(ret);
                exit_ping(EXIT_FAILURE);
            }
        }
        ret[j++] = value;
    }
    ret[j] = '\0';

    return ret;
}

int get_optarg_number(char *optarg, void *dest, long min_max[2], __uint8_t dest_size) {
    long min = min_max[0];
    long max = min_max[1];
    unsigned long n;
    char *endptr;

    errno = 0;
    n = strtoul(optarg, &endptr, 0);

    if (endptr == optarg || *endptr) {
        fprintf(stderr, "%s: invalid value (`%s' near `%s')\n", PROG_NAME, optarg, endptr);
        return EXIT_FAILURE;
    } else if (max != -1 && n > (unsigned long)max) {
        fprintf(stderr, "%s: option value too big: %s\n", PROG_NAME, optarg);
        return EXIT_FAILURE;
    } else if (min != -1 && n < (unsigned long)min) {
        fprintf(stderr, "%s: option value too small: %s\n", PROG_NAME, optarg);
        return EXIT_FAILURE;
    }

    memcpy(dest, &n, dest_size);
    return EXIT_SUCCESS;
}

void get_options(int argc, char **argv) {
    int opt;
    int ret;
    struct option long_options[] = {
        {"count", required_argument, 0, 'c'},
        {"interval", required_argument, 0, 'i'},
        {"pattern", required_argument, 0, 'p'},
        {"ttl", required_argument, 0, 't'},
        {"size", required_argument, 0, 's'},
        {"verbose", no_argument, 0, 'v'},
        {"timeout", required_argument, 0, 'w'},
        {"linger", required_argument, 0, 'W'},
        {"usage", no_argument, 0, 'u'},
        {"help", no_argument, 0, '?'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "c:i:p:s:t:vw:W:?", long_options, NULL)) != -1) {
        switch(opt) {
            case '?':
                if (strcmp(argv[optind - 1], "-?") == 0 || strcmp(argv[optind - 1], "--help") == 0) {
                    exit_help(EXIT_SUCCESS);
                } else {
                    exit_error_usage(64);
                }
                break;
            case 'c':
                g_ft_ping.options.flags |= COUNT;
                if ((ret = get_optarg_number(optarg, &g_ft_ping.options.count,
                        (long [2]){MIN_COUNT, MAX_COUNT}, sizeof(g_ft_ping.options.count))) != EXIT_SUCCESS) {
                    exit_ping(ret);
                }
                break;
            case 'i':
                g_ft_ping.options.flags |= INTERVAL;
                if ((ret = get_optarg_number(optarg, &g_ft_ping.options.interval,
                        (long [2]){MIN_INTERVAL, MAX_INTERVAL}, sizeof(g_ft_ping.options.interval))) != EXIT_SUCCESS) {
                    exit_ping(ret);
                }
                break;
            case 'v':
                g_ft_ping.options.flags |= VERBOSE;
                break;
            case 't':
                g_ft_ping.options.flags |= TTL;
                if ((ret = get_optarg_number(optarg, &g_ft_ping.options.ttl,
                        (long [2]){MIN_TTL, MAX_TTL}, sizeof(g_ft_ping.options.ttl))) != EXIT_SUCCESS) {
                    exit_ping(ret);
                }
                break;
            case 'u':
                exit_usage(EXIT_SUCCESS);
                break;
            case 'w':
                g_ft_ping.options.flags |= TIMEOUT;
                if ((ret = get_optarg_number(optarg, &g_ft_ping.options.timeout,
                        (long [2]){MIN_TIMEOUT, MAX_TIMEOUT}, sizeof(g_ft_ping.options.timeout))) != EXIT_SUCCESS) {
                    exit_ping(ret);
                }
                break;
            case 'W':
                g_ft_ping.options.flags |= LINGER;
                if ((ret = get_optarg_number(optarg, &g_ft_ping.options.linger,
                        (long [2]){MIN_LINGER, MAX_LINGER}, sizeof(g_ft_ping.options.linger))) != EXIT_SUCCESS) {
                    exit_ping(ret);
                }
                break;
            case 'p':
                g_ft_ping.options.flags |= PATTERN;
                if (g_ft_ping.options.pattern) {
                    free(g_ft_ping.options.pattern);
                    g_ft_ping.options.pattern = DEFAULT_PATTERN;
                }
                ssize_t len = strlen(optarg);
                g_ft_ping.options.pattern = hex_to_value_string(optarg, len);
                g_ft_ping.options.pattern_size = (len % 2 == 0 ? len : len + 1) / 2;
                break;
            case 's':
                g_ft_ping.options.flags |= SIZE;
                if ((ret = get_optarg_number(optarg, &g_ft_ping.options.data_packet_size,
                        (long [2]){MIN_DATA_PACKET_SIZE, MAX_DATA_PACKET_SIZE}, sizeof(g_ft_ping.options.data_packet_size))) != EXIT_SUCCESS) {
                    exit_ping(ret);
                }
                break;
            default:
                exit_error_usage(EXIT_FAILURE);
                break;
        }
    }
}