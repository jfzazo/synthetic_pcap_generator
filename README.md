# PCAP trace generator.

This utility allows a developer to generate synthetic traces given a list of values. It does not require from any other third party library but you *must* count with the mergecap utility under your system path.

## Compilation

As simple as running:
    
    make

## Running the program

If you invoke the program without arguments, it will display the help of the program:

    perl run.pl

That I believe that is self-explanatory,

  perl run.pl <list of integer with multiplicity>

  Examples:
     perl run.pl 63 -> Creates a trace with a single packet of size 63
     perl run.pl 5x63 -> Creates a trace with 5 packets of size 63
     perl run.pl 5x63 71 -> Creates a trace with 5 packets of size 63 followed by one packet of 73B



