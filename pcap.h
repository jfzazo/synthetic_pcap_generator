#ifndef NFP_PCAP_H
#define NFP_PCAP_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>



/* PCAP description */
/*

++---------------++---------------+-------------++---------------+-------------++---------------+-------------++
|| Global Header || Packet Header | Packet Data || Packet Header | Packet Data || Packet Header | Packet Data ||
++---------------++---------------+-------------++---------------+-------------++---------------+-------------++

...

*/


/* Global header */
typedef struct pcap_hdr_s {
  uint32_t magic_number;   /* magic number */
  uint16_t version_major;  /* major version number */
  uint16_t version_minor;  /* minor version number */
  uint32_t thiszone;       /* GMT to local correction */
  uint32_t sigfigs;        /* accuracy of timestamps */
  uint32_t snaplen;        /* max length of captured packets, in octets */
  uint32_t network;        /* data link type */
} pcap_hdr_t;

/* Packet header */
typedef struct pcaprec_hdr_s {
  uint32_t ts_sec;         /* timestamp seconds */
  uint32_t ts_usec;        /* timestamp microseconds */
  uint32_t incl_len;       /* number of octets of packet saved in file */
  uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;


/* Real information used in the callback function */
struct pcap_pkthdr {
  uint32_t len;
  struct timeval ts;
};


FILE *pcap_open (char *path);

void pcap_close (FILE *descriptor);

int pcap_generate (unsigned long int size_file, unsigned long int ifg, unsigned char use_crc,FILE* in, FILE* out);

#endif
