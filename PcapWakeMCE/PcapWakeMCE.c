#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>

#define LINE_LEN 16

#define PACKET_SIZE 116

int copy_mac(char *target, u_char *p_packet)
{
	char digit;
	int i;
	u_char j, val, factor;

	if (strlen(target) != 17)
	{
		return (-1);
	}
	for (i = 0; i < 5; i++)
	{
		if (target[2 + i * 3] != ':')
		{
			return (-1);
		}
	}

	/* Cycle trough the 6 bytes of the MAC */
	for (i = 0; i < 6; i++)
	{
		val = 0;

		/* Cycle trough the 2 digits of the hex value */
		for (j = 0; j < 2; j++)
		{
			digit = *target++;
			if (j == 0)
			{
				/* Left digit of hex value */
				factor = 0x10;
			}
			else
			{
				/* Right digit of hex value */
				factor = 0x01;
			}
			if(digit >= '0' && digit <= '9')
			{
				val += factor * (digit - '0');
			}
			else if (digit >= 'a' && digit <= 'f')
			{
				val += factor * (digit - 'a' + 10);
			}
			else if (digit >= 'A' && digit <= 'F')
			{
				val += factor * (digit - 'A' + 10);
			}
			else
			{
				return (-1);
			}
		}
		p_packet[i] = (u_char)val;
		target++;
	}

	return 0;

}

int main(int argc, char **argv)
{	
	pcap_if_t *alldevs, *d;
	pcap_t *fp;
	u_int inum, ui=0;
	char errbuf[PCAP_ERRBUF_SIZE];
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	char *source = NULL;
	char *target = NULL;
	char *filter = NULL;
	bpf_u_int32 NetMask;
	struct bpf_program fcode;
	int p;
	const char *filter_prefix = "ether src ";
	u_char packet[PACKET_SIZE];
	int i;

	printf("PcapWakeMCE: Wakes a Mediacenter PC if a en extender tries to connect.\n\n");
	printf("Usage: PcapWakeMCE [-s source] [-f filter] [-t target]\n"
		"    -s interface or file to listen for packets\n"
		"       if not provided a list of available interfaces will be displayed\n"
		"    -f MAC address of the extender to listen for\n"
		"       if not provided PcapWakeMCE will listen for any packet (for testing\n"
		"       only)\n"
		"    -t MAC address of the Mediacenter PC to Wake on LAN\n"
		"       if not provided no WoL packets will be sent (for testing only)\n\n"
		"Examples:\n"
		"  PcapWakeMCE -s \\Device\\NPF_{C8736017-F3C3-4373-94AC-9A34B7DAD998} -f\n"
		"  00:1d:7e:a4:0f:b8 -t 00:18:f3:6c:69:d9\n\n"
		"  PcapWakeMCE -s file.acp -f 00:1d:7e:a4:0f:b8 -t 00:18:f3:6c:69:d9\n"
		"  (for testing only)\n\n");


	/* Parse parameters */
	for(p=1; p < argc; p+= 2)
	{
		switch (argv[p] [1])
		{
			case 's':
			{
				source=argv[p+1];
			};
			break;
			
			case 't':
			{
				target=argv[p+1];
			};
			break;

			case 'f':
			{
				filter = (char *)calloc(strlen(filter_prefix) + strlen(argv[p+1]) + 1, 
                        sizeof(char));
				strcat(filter, filter_prefix);
				strcat(filter, argv[p+1]);
			};
			break;
		}
	}


	if(source == NULL)
	{
		printf("\nNo adapter selected: printing the device list:\n");
		/* The user didn't provide a packet source: Retrieve the local device list */
		if(pcap_findalldevs(&alldevs, errbuf) == -1)
		{
			fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
			exit(1);
		}
		
		/* Print the list */
		for(d=alldevs; d; d=d->next)
		{
			printf("%d. %s\n    ", ++ui, d->name);

			if (d->description)
				printf(" (%s)\n", d->description);
			else
				printf(" (No description available)\n");
		}
		
		if (ui==0)
		{
			printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
			return -1;
		}
		
		printf("Enter the interface number (1-%d):",ui);
		scanf("%d", &inum);
		
		if (inum < 1 || inum > ui)
		{
			printf("\nInterface number out of range.\n");

			/* Free the device list */
			pcap_freealldevs(alldevs);
			return -1;
		}
		
		/* Jump to the selected adapter */
		for (d=alldevs, ui=0; ui< inum-1 ;d=d->next, ui++);
		
		source = d->name;
	}

	if (target != NULL)
	{
		/* Set mac destination to Broadcast */
		copy_mac("FF:FF:FF:FF:FF:FF", &packet[0]);
		
		/* set mac source to 01:01:01:01:01:01 */
		copy_mac("01:01:01:01:01:01", &packet[6]);

		packet[12] = 0x08;
		packet[13] = 0x42;

		/* 6 x 0xFF */
		copy_mac("FF:FF:FF:FF:FF:FF", &packet[14]);

		/* 16 x MAC */
		for (i = 20; i < PACKET_SIZE; i += 6)
		{
			if(copy_mac(target, &packet[i])<0)
			{
				fprintf(stderr,"\nInvalid target MAC address.\n");
				return -5;
			}
		}
	}



	do
	{
		/* Open the adapter */
		if ((fp = pcap_open_live(source,	// name of the device
			65536,							// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
			1,								// promiscuous mode (nonzero means promiscuous)
			1000,							// read timeout
			errbuf							// error buffer
			)) == NULL)
		{
			fprintf(stderr,"\nError opening adapter.\n");
			return -1;
		}


		if (filter != NULL)
		{
			NetMask=0;

			//compile the filter
			if(pcap_compile(fp, &fcode, filter, 1, NetMask) < 0)
			{
				fprintf(stderr,"\nError compiling filter: invalid MAC address.\n");

				pcap_close(fp);
				return -3;
			}

			//set the filter
			if(pcap_setfilter(fp, &fcode)<0)
			{
				fprintf(stderr,"\nError setting the filter.\n");

				pcap_close(fp);
				return -4;
			}

		}

		if (filter != NULL)
		{
			printf("\nWaiting for a packet from %s...\n", filter);
		}
		else
		{
			printf("\nWaiting for a packet from any device...\n");
		}

		/* Read the packets */
		while((res = pcap_next_ex(fp, &header, &pkt_data)) == 0)
		{
			/* Timeout elapsed */
		}

		printf("\nReceived a packet:\n");			

		/* print pkt timestamp and pkt len */
		printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);			
		
		/* Print the packet */
		for (ui=1; (ui < header->caplen + 1 ) ; ui++)
		{
			printf("%.2x ", pkt_data[ui-1]);
			if ( (ui % LINE_LEN) == 0) printf("\n");
		}
		
		printf("\n\n");		

		if (target != NULL)
		{
			/* Send down the Wake on LAN packet */
			if (pcap_sendpacket(fp,	// Adapter
				packet,				// buffer with the packet
				PACKET_SIZE			// size
				) == 0)
			{
				printf("\nSent WoL packet for %s\n", target);
			}
			else
			{
				fprintf(stderr,"\nError sending the WoL packet: %s\n", pcap_geterr(fp));
				return 3;
			}
		}

		/* Stop capturing to prevent the buffer filling up while pausing */
		pcap_close(fp);

		printf("Listening paused for 30 seconds to prevent flooding the LAN with WoL packets...\n");
		Sleep(30000);

	} while (res >= 0);

	if(res == -1)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(fp));
		return -1;
	}

	//pcap_close(fp);
	return 0;
}
