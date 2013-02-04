#include <pcap.h>
#include <stdio.h>
#include <time.h>
#include <signal.h>
#include <libnet.h>

#include <netinet/if_ether.h>

#include "lltd.c"

#define PCAP_PERIOD 100 // pcap kernel poll period, ms

void usage(char *name) {
        fprintf(stderr,
                "usage: %s [-i iface] [-t timeout] [-u] [-v] [-v] [aa:bb:cc:dd:ee:ff]\n\n"
		"\t timeout is in milliseconds;\n"
		"\t add -u to show machine names in UTF-8;\n"
		"\t add -v or -vv increase verbosity;\n"
		"\t last argument is an optional single MAC-address of interest.\n",
                name);
}

static int do_stop=0;
static timer_t timer_id;
static struct timeval start_time;
static int verbose = 0;
static int unicode = 0;

static uint64_t hosts[200];
static int nhosts = 0;

static u_char* mac_to_find = NULL;
static int mac_found = 0;

static pcap_t *pcap_handle;

// converts timeval diff to milliseconds
long tv_diff2msec(const struct timeval*ptv){
	struct timeval curtime;
	if(!ptv){
		gettimeofday(&curtime, NULL);
		ptv = &curtime;
	}
	time_t dsec = ptv->tv_sec - start_time.tv_sec;
	long  dmsec = (ptv->tv_usec - start_time.tv_usec)/1000;
	while( dsec > 0 ){
		dsec--;
		dmsec += 1000;
	}
	return dmsec;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	time_t dsec;
	suseconds_t dmsec;
	u_char *p;
	int i,j;
	uint64_t host_id=0;
	char mac[0x20];

	if( header->caplen < 100) return; // skip some unknown very small pkts

	memcpy(&host_id, packet+48, 6);
	for(i=0; i<nhosts; i++){
		// host already responded
		if(hosts[i] == host_id) return;
	}
	hosts[nhosts++] = host_id;

	sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
		packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]
	);

	if( mac_to_find ){
		if( 0 == strcasecmp(mac, mac_to_find) ){
			nhosts = 1;
			do_stop = 1;
			mac_found = 1;
			pcap_breakloop( pcap_handle );
		} else 
			return;
	}

	printf("%3d bytes from %s (%-15s): time=%3d ms name=\"%s\"",
		header->caplen,
		mac,
		lltd_extract_ip(packet+46),
		tv_diff2msec(&header->ts),
		unicode ? lltd_extract_unicode_name(packet+46) : lltd_extract_name(packet+46)
	);

	if(verbose == 1){
		puts("");
		lltd_dump(packet+46);
	} else if(verbose == 2){
		printf("\n\t");
		for(i=46,j=0; i<header->caplen; i++){
			printf("%02x ",packet[i]);
			j++;
			if(j == 16){ printf("\n\t"); j=0; }
		}
	}
	puts("");
}

void on_alarm(int v){
	do_stop = 1;
}

#if PCAP_ERRBUF_SIZE > LIBNET_ERRBUF_SIZE
#define ERRBUF_SIZE PCAP_ERRBUF_SIZE
#else
#define ERRBUF_SIZE LIBNET_ERRBUF_SIZE
#endif

int main (int argc, char *argv[]){
	char           *dev = NULL;
	char		errbuf    [ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;	/* The compiled filter */
	char		filter_exp[] = "ether proto 0x88d9"; //"port 80";	/* The filter expression */
	bpf_u_int32	mask;	/* Our netmask */
	bpf_u_int32	net;	/* Our IP */
	struct pcap_pkthdr header;
	const u_char   *packet;
	int c,i;
	libnet_t       *l;
	libnet_ptag_t   eth_ptag = 0;
	u_char buf[0x100];
	struct itimerspec tspec;

	memset(&tspec, 0, sizeof(tspec));
	tspec.it_value.tv_sec = 3;

        while ((c = getopt(argc, argv, "t:i:hvu")) != EOF) {
                switch (c) {
                case 'i': // interface
                        dev = optarg;
                        break;
                case 't': // timeout
			i = atoi(optarg);
			if( i>0 ){
#ifndef __linux__				
				if( i > PCAP_PERIOD ) i-=PCAP_PERIOD-10; // try to be more precise
#endif				
				tspec.it_value.tv_sec = i/1000;
				tspec.it_value.tv_nsec = (i%1000)*1000000;
			}
                        break;
                case 'v': // verbosity
                        verbose++;
                        break;
                case 'u': // unicode support
                        unicode = 1;
                        break;
                case 'h': // show usage
                        usage(argv[0]);
                        exit(EXIT_SUCCESS);
                default:
                        exit(EXIT_FAILURE);
                }
        }
	argc -= optind; argv += optind;

	if( argc > 1 ){
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	if( argc == 1 ){
		if( strlen(argv[0]) != 17 ){
			fprintf(stderr, "Invalid MAC-address: '%s'\n", argv[0]);
                        exit(EXIT_FAILURE);
		}
		mac_to_find = argv[0];
	}

	setlinebuf(stdout);

	if(!dev) dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return (2);
	}

	printf("interface %s\n",dev);

        l = libnet_init(LIBNET_LINK, dev, errbuf);
        if (l == NULL) {
                fprintf(stderr, "libnet_init() failed: %s", errbuf);
                exit(EXIT_FAILURE);
        }

	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	struct ether_addr *ha = NULL;
	if ((ha = (struct ether_addr *) libnet_get_hwaddr(l)) == NULL) {
		fprintf(stderr, "%s", libnet_geterror(l));
		exit(EXIT_FAILURE);
	}

        // LLTP magic packet
        char* payload = "\x01\x00\x00\x00\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00";
        char* hwdst   = "\xff\xff\xff\xff\xff\xff";

	memcpy(buf,payload,18);
	memcpy(buf+10, ha, 6);

	gettimeofday(&start_time, NULL);
	memcpy(buf+16, &start_time.tv_sec, 2); // emulate sequence number

        eth_ptag = libnet_build_ethernet(
                                         hwdst, /* ethernet destination */
                                         ha->ether_addr_octet,
                                                        /* ethernet source */
                                         0x88d9,        /* protocol type */
                                         buf,       /* payload */
                                         18,    /* payload size */
                                         l,     /* libnet handle */
                                         0);    /* libnet id */
        if (eth_ptag == -1) {
                fprintf(stderr, "Can't build ethernet header: %s\n", libnet_geterror(l));
		libnet_destroy(l);
		exit(EXIT_FAILURE);
        }
        /*
         * Write it to the wire.
         */
        c = libnet_write(l);

	if (c == -1) {
                fprintf(stderr, "Write error: %s\n", libnet_geterror(l));
		libnet_destroy(l);
		exit(EXIT_FAILURE);
	}

	/* Open the session in promiscuous mode */
	pcap_handle = pcap_open_live(dev, BUFSIZ, 1, PCAP_PERIOD, errbuf);
	if (pcap_handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		libnet_destroy(l);
		return (2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(pcap_handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(pcap_handle));
		libnet_destroy(l);
		return (2);
	}
	if (pcap_setfilter(pcap_handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(pcap_handle));
		libnet_destroy(l);
		return (2);
	}

	signal(SIGALRM, on_alarm);

	gettimeofday(&start_time, NULL);
	
	timer_create(CLOCK_MONOTONIC, NULL, &timer_id);
	timer_settime(timer_id, 0, &tspec, NULL);

	// don't know why, but pcap_dispatch does not return control to main after
	// timeout expires. so, we use nonblocking pcap on linux.
#ifdef __linux__
	pcap_setnonblock(pcap_handle, 1, errbuf);
#endif

	while( !do_stop ){
		pcap_dispatch(pcap_handle, -1, got_packet, NULL);
#ifdef __linux__
		usleep(1000);
#endif
	}

	pcap_close(pcap_handle);

	i = tv_diff2msec(NULL);

	printf("found %d hosts in %d.%d seconds", nhosts, i/1000, i%1000);

	if( mac_to_find && !mac_found ){
		printf(", but '%s' is not found.\n", mac_to_find);
	} else {
		puts("");
	}

	return (0);
}
