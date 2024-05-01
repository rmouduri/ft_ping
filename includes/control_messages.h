#ifndef _CONTROL_MESSAGES_H_
#define _CONTROL_MESSAGES_H_


typedef enum e_icmp_error_type {
    E_ECHO_REPLY = 0,
    E_DESTINATION_UNREACHABLE = 3,
    E_SOURCE_QUENCH = 4,
    E_REDIRECT = 5,
    E_ECHO_REQUEST = 8,
    E_TIME_EXCEEDED = 11,
    E_PARAMETER_PROBLEM = 12,
    E_TIMESTAMP_REQUEST = 13,
    E_TIMESTAMP_REPLY = 14,
    E_ADDRESS_MASK_REQUEST = 17,
    E_ADDRESS_MASK_REPLY = 18
} icmp_error_type;

#define ICMP_ERROR_CODES { \
    /* E_ECHO_REPLY (0) */ \
    { "Echo reply" }, \
    {}, \
    {}, \
\
    /* E_DESTINATION_UNREACHABLE (3) */ \
    { "Network Unreachable", \
      "Host Unreachable", \
      "Protocol Unreachable", \
      "Port Unreachable", \
      "Fragmentation Needed and DF Set", \
      "Source Route Failed", \
      "Destination Network Unknown", \
      "Destination Host Unknown", \
      "Source Host Isolated", \
      "Communication with Destination Network Administratively Prohibited", \
      "Communication with Destination Host Administratively Prohibited", \
      "Network Unreachable for TOS", \
      "Host Unreachable for TOS", \
      "Communication Administratively Prohibited by Filtering" }, \
\
    /* E_SOURCE_QUENCH (4) */ \
    { "Source Quench" }, \
\
    /* E_REDIRECT (5) */ \
    { "Redirect Datagram for the Network", \
      "Redirect Datagram for the Host", \
      "Redirect Datagram for the TOS & Network", \
      "Redirect Datagram for the TOS & Host" }, \
    {}, \
    {}, \
\
    /* E_ECHO_REQUEST (8) */ \
    { "Echo request" }, \
    {}, \
    {}, \
\
    /* E_TIME_EXCEEDED (11) */ \
    { "Time to Live Exceeded", \
      "Fragment Reassembly Time Exceeded" }, \
\
    /* E_PARAMETER_PROBLEM (12) */ \
    { "Pointer Indicates the Error", \
      "Missing a Required Option", \
      "Bad Length" }, \
\
    /* E_TIMESTAMP_REQUEST (13) */ \
    { "Timestamp Request" }, \
\
    /* E_TIMESTAMP_REPLY (14) */ \
    { "Timestamp Reply" }, \
    {}, \
    {}, \
\
    /* E_ADDRESS_MASK_REQUEST (17) */ \
    { "Address Mask Request" }, \
\
    /* E_ADDRESS_MASK_REPLY (18) */ \
    { "Address Mask Reply" } \
}


#endif // _CONTROL_MESSAGES_H_