#ifndef _FT_PING_H_
#define _FT_PING_H_

#include <limits.h>
#include <netinet/in.h>

#define PROG_NAME	"ft_ping"

#define PING_HELP	"Usage: "PROG_NAME" [OPTION...] HOST ...\n" \
					"Send ICMP ECHO_REQUEST packets to network hosts.\n" \
					"\n" \
					" Options valid for all request types:\n" \
					"\n" \
					"  -c, --count=NUMBER        stop after sending NUMBER packets\n" \
					"  -i, --interval=NUMBER     wait NUMBER seconds between sending each packet\n" \
					"      --ttl=N               specify N as time-to-live\n" \
					"  -v, --verbose             verbose output\n" \
					"  -w, --timeout=N           stop after N seconds\n" \
					"  -W, --linger=N            number of seconds to wait for response\n" \
					"\n" \
					" Option valid for --echo requests:\n" \
					"\n" \
					"  -p, --pattern=PATTERN     fill ICMP packet with given pattern (hex)\n" \
					"  -s, --size=NUMBER         send NUMBER data octets\n" \
					"\n" \
					"  -?, --help                give this help list\n" \
					"      --usage               give a short usage message\n"

#define PING_USAGE	"Usage: "PROG_NAME" [-v?] [-c NUMBER] [-i NUMBER] [-w N]\n" \
					"               [-W N] [-p PATTERN] [-s NUMBER]\n" \
					"               [--count=NUMBER]\n" \
					"               [--interval=NUMBER] [--ttl=N]\n" \
					"               [--verbose] [--timeout=N] [--linger=N]\n" \
					"               [--pattern=PATTERN]\n" \
					"               [--size=NUMBER] [--help] [--usage]\n" \
					"               HOST ..."

#define PING_ERROR_USAGE	"Try '"PROG_NAME" --help' or '"PROG_NAME" --usage' for more information."
#define PING_MISSING_HOST	PROG_NAME": missing host operand"
#define PING_UNKNOWN_HOST	PROG_NAME": unknown host"
#define PING_IPV6_SUPPORT	PROG_NAME": ipv6 not supported"
#define PING_DUPE_ERROR		" (DUP!)"


#define MIN_DATA_PACKET_SIZE	0
#define MAX_DATA_PACKET_SIZE	65399
#define MIN_COUNT		1
#define MAX_COUNT		LONG_MAX
#define MIN_INTERVAL	1
#define MAX_INTERVAL	INT_MAX
#define MIN_LINGER		1
#define MAX_LINGER		INT_MAX
#define MIN_TIMEOUT		1
#define MAX_TIMEOUT		INT_MAX
#define MIN_TTL			1
#define MAX_TTL			UCHAR_MAX


#define DEFAULT_COUNT			-1
#define DEFAULT_INTERVAL		1
#define DEFAULT_LINGER			1
#define DEFAULT_DATA_PACKET_SIZE		56
#define DEFAULT_TIMEOUT			-1
#define DEFAULT_TTL				64
#define DEFAULT_PATTERN			NULL



typedef enum e_options_flag {
	VERBOSE		=	1 << 0,
	TTL			= 	1 << 1,
	TIMEOUT		=	1 << 2,
	LINGER		=	1 << 3,
	PATTERN		=	1 << 4,
	SIZE		=	1 << 5,
	COUNT		=	1 << 6,
	INTERVAL	=	1 << 7
} t_options_flag;

typedef enum e_address_type {
    NONE,
    IPV4,
    IPV6,
    FQDN
} address_type;

typedef struct s_options {
	t_options_flag	flags;

	uint64_t		count;
	uint32_t		interval;
	uint32_t		linger;
	uint16_t		data_packet_size;
	uint32_t		timeout;
	uint8_t			ttl;
	unsigned char *	pattern;
	ssize_t			pattern_size;
} t_options;


typedef struct s_ft_ping {
	t_options		options;

	char *			host_arg_name;
	int				sockfd;
	address_type	address_type;

    struct addrinfo		*res;
	struct sockaddr_in	sa4;

	uint8_t			packet[USHRT_MAX];
	uint8_t			buffer[USHRT_MAX];

	uint64_t		packets_sent;
	uint64_t		packets_received;
	uint8_t			seq_packets_sent[USHRT_MAX / 8 + 1];
} t_ft_ping;



extern t_ft_ping g_ft_ping;


// options.c
void get_options(int argc, char **argv);
void print_ft_ping_global(void);


// ping.c
void init_socket(void);
void print_statistics(void);
void ping_loop(void);


// error.c
void exit_ping(int ret);
void exit_missing_host(int ret);
void exit_error_usage(int ret);
void exit_help(int ret);
void exit_usage(int ret);
void exit_statistics(int ret);
void exit_ipv6_support(int ret);
void exit_unknown_host(int ret);


#endif //_FT_PING_H_