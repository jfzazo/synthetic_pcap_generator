#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "pcap.h"

#define ETHERNET_HEADER_SIZE 14

struct arguments {
  uint64_t size;
  FILE     *output;
};

static void printUsage()
{
  fprintf (stderr, "Usage:\n"
           "\tgenpacket [OPTION] \n\n"
           "\t-s SIZE, specify  minimum size of the packet (at least 14 bytes).\n"
           "\t-o output.pcap, output with the new pcap.\n"
          );
}


static int readArguments (int argc, char **argv, struct arguments *arg)
{
  int i, rmember;
  char unit;
  unsigned long int size;

  if (argc<2 || argc > 8) {
    return -1;
  }

  arg->output = stdout;  arg->size=0;

  for (i=1; i<argc-1; i++) {
    if (!strcmp (argv[i], "-s")) {
      i++;
      rmember = sscanf (argv[i], "%ld%c", &size, &unit);

      if (rmember == 2) {
        if (toupper (unit) =='G') {
          size*=1024*1024*1024;
        } else if (toupper (unit) =='M') {
          size*=1024*1024;
        } else if (toupper (unit) =='K') {
          size*=1024;
        }
      }

      arg->size=size;
    } else if (!strcmp (argv[i], "-o")) {
      i++;
      arg->output = fopen (argv[i],"w");
    } else {
      return -1;
    }
  }

  return 0;
}

int main (int argc, char **argv)
{
  struct arguments arg;
  pcap_hdr_t gheader;
  pcaprec_hdr_t lheader;
  unsigned char *field;
  int i;
  struct timeval t;

  if (readArguments (argc, argv, &arg) || arg.size < ETHERNET_HEADER_SIZE) {
    printUsage();
    return 0;
  }

  field=malloc (arg.size);
  /*
  Generar un paquete en fichero pcap. Para ello añadir la cabecera global, local y el contenido,
  paquete ethernet del tamaño especificado.
  */
  gheader.magic_number  = 0xA1B2C3D4;
  gheader.version_major = 0x0002;
  gheader.version_minor = 0x0004;
  gheader.thiszone      = 0x00000000;
  gheader.sigfigs       = 0x00000000;
  gheader.snaplen       = 0xFFFF;
  gheader.network       = 0x00000001;
  fwrite (&gheader, sizeof (pcap_hdr_t), 1, arg.output);
  /*  Copy local header */
  gettimeofday (&t, NULL);
  lheader.ts_sec = t.tv_sec;
  lheader.ts_usec = t.tv_usec;
  lheader.incl_len = arg.size;
  lheader.orig_len = arg.size;
  fwrite (&lheader, sizeof (pcaprec_hdr_t), 1, arg.output);

  /* Copy  MAC's. */
  for (i=0; i<6; i++) {
    field[i] = i;
  }

  fwrite (field, 1, 6, arg.output);

  for (i=5; i>=0; i--) {
    field[i] = i;
  }

  fwrite (field, 1, 6, arg.output);

  for (i=1; i>=0; i--) {
    field[i] = 0;
  }

  /* Protocol = 0x0800 IP */
  uint16_t size = arg.size - ETHERNET_HEADER_SIZE;  // Restamos la cabecera ethernet y el crc.
  * ( (uint16_t *) field) = htons (size);
  fwrite (field, 1, 2, arg.output);

  /* Complete with random values */
  for (i=0; i<size; i++) {
    field[i] = rand();
  }

  fwrite (field, 1, size, arg.output);
  fclose (arg.output);
  free (field);
  return 0;
}