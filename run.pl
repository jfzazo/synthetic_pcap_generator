use strict;
use warnings;

sub printUsage{
   print "Mode of usage:\n";
   print "  perl run.pl <list of integer with multiplicity>\n";
   print "\n";
   print "  Examples:\n";
   print "     perl run.pl 63 -> Creates a trace with a single packet of size 63\n";
   print "     perl run.pl 5x63 -> Creates a trace with 5 packets of size 63\n";
   print "     perl run.pl 5x63 71 -> Creates a trace with 5 packets of size 63 followed by one packet of 73B\n";
   print "\n";
   print "\n";
}

my @sizes = ();
my @multiplicity = ();


if($#ARGV+3==0) {
	printUsage();
	die;
}

my $operator = $ARGV[0];
my $ofile = $ARGV[1];

if($operator ne "-w") {
	printUsage();
	die;
}

foreach my $argnum (2 .. $#ARGV) {
	if ( $ARGV[$argnum] =~ /(\d+)x(\d+)/ ) {
		$sizes[$argnum] = $2;
		$multiplicity[$argnum] = $1;
	} elsif($ARGV[$argnum] =~ /(\d+)/) {
		$sizes[$argnum] = $1;
		$multiplicity[$argnum] = 1;
	} else {
		printUsage();
		die;
	}

	if($sizes[$argnum]<14) {
		die "The size of the packets must be greater than 14B (input provided: $sizes[$argnum])";
	}
}

my $pcaps_files="";
for my $i (2 .. $#ARGV) {
	my $csize = $sizes[$i];

	`./genpacket -s $csize -o $csize.$i.pcap`;
	$pcaps_files=$pcaps_files."$csize.$i.pcap ";

	if($multiplicity[$i] > 1) {
		my $iters = $multiplicity[$i]-1;
		my $repeated_pcap_chain = "";
		for my $j (0 .. $iters) {
			$repeated_pcap_chain = $repeated_pcap_chain." $csize.$i.pcap"
		}
		`mergecap  $repeated_pcap_chain -w $csize.$i.bak -F pcap`;
		`mv $csize.$i.bak $csize.$i.pcap`;

	}
}


`mergecap $pcaps_files -w $ofile -F pcap`;


`rm $pcaps_files`;


