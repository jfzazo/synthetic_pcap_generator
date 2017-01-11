#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include "pcap.h"

struct arguments {
  uint64_t size;
  uint64_t ifg;
  unsigned char crc;
  FILE     *input;
  FILE     *output;
};

static void printUsage()
{
  fprintf (stderr, "Usage:\n"
           "\tgenpcap [OPTION] input.pcap\n\n"
           "Option can be:\n"
           "\t-s SIZE, specify the minimum size of the output (packets in input.pcap will be concatenate N times).\n"
           "\t-i SIZE, specify the interframe gap between packets.\n"
           "\t-crc, add the ethernet CRC.\n"
           "\t-o output.pcap, output with the new pcap.\n"
          );
}

static char *file_name;

static int readArguments (int argc, char **argv, struct arguments *arg)
{
  int i, rmember;
  char unit;
  unsigned long int size;

  if (argc<2 || argc > 9) {
    return -1;
  }

  arg->output = stdout; arg->ifg=0; arg->size=0; arg->crc = 0;

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
    } else if (!strcmp (argv[i], "-i")) {
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

      arg->ifg=size;
    } else if (!strcmp (argv[i], "-crc")) {
      arg->crc = 1;
    } else if (!strcmp (argv[i], "-o")) {
      i++;
      file_name = argv[i];
      arg->output = fopen (argv[i],"w");
    } else {
      return -1;
    }
  }

  arg->input = pcap_open (argv[argc-1]);

  if (arg->input==NULL) {
    if (arg->output!=stdout) {
      fclose (arg->output);
    }

    return -1;
  }

  return 0;
}

int main (int argc, char **argv)
{
  struct arguments arg;

  if (readArguments (argc, argv, &arg)) {
    printUsage();
    return 0;
  }

  if (pcap_generate (arg.size,arg.ifg,  arg.crc, arg.input, arg.output)) {
    fprintf (stderr,"There was an error\n");
  } else {
    if (file_name) {
      fprintf (stderr,"File %s successfully created\n", file_name);
    }
  }

  if (arg.output!=stdout) {
    fclose (arg.output);
  }

  pcap_close (arg.input);
  return 0;
}