#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}
void Mac_addr(const u_char* packet) {
    struct libnet_ethernet_hdr * eth = (struct libnet_ethernet_hdr *) packet;
    printf("====Mac_Dst====\n");
    for(int i=0; i<6; i++){
        printf("%02x", eth->ether_dhost[i]);
        if(i!=5)
            printf(":");
        else
            printf("\n");
    }
    printf("====Mac_Src====\n");
    for(int i=0; i<6; i++){
        printf("%02x", eth->ether_shost[i]);
        if(i!=5)
            printf(":");
        else
            printf("\n");
    }
}

void IP_addr(const u_char* packet) {
    struct libnet_ipv4_hdr * ip_ad = (struct libnet_ipv4_hdr *)(packet + 14);
    uint32_t src_ip_32 = ip_ad -> ip_src.s_addr;
    uint32_t dst_ip_32 = ip_ad -> ip_dst.s_addr;
    uint8_t src_ip_8[] = {(src_ip_32 & 0xff),
                          ((src_ip_32 >> 8) & 0xff),
                          ((src_ip_32 >> 16)& 0xff),
                          ((src_ip_32 >> 24)& 0xff)};
    printf("====Ip_src_Addr====\n");
    for(int i=0; i<4; i++){
        printf("%d", (src_ip_8[i]));
        if(i!=3)
            printf(".");
        else
            printf("\n");
    }
    uint8_t dst_ip_8[] = {(dst_ip_32 & 0xff),
                          ((dst_ip_32 >> 8) & 0xff),
                          ((dst_ip_32 >> 16)& 0xff),
                          ((dst_ip_32 >> 24)& 0xff)};
    printf("====Ip_dst_Addr====\n");
    for(int i=0; i<4; i++){
        printf("%d", (dst_ip_8[i]));
        if(i!=3)
            printf(".");
        else
            printf("\n");
    }

}

void Tcp(const u_char* packet) {
    struct libnet_tcp_hdr * tcp = (struct libnet_tcp_hdr *)(packet + 34);
    printf("====src port====\n");
    printf("%d\n", ntohs(tcp->th_sport));
    printf("====dst port====\n");
    printf("%d\n", ntohs(tcp->th_dport));
}

void Data(const u_char* packet){
    const u_char* payload = packet + 54;
    if((payload) == NULL)
        printf("Not Found Data!!");
    else{
        printf("====Data====\n");
        for(int i=0; i<8; i++)
            printf("%02x ", (payload[i]));
    }
    printf("\n\n");

}
int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);

        Mac_addr(packet);
        IP_addr(packet);
        Tcp(packet);
        Data(packet);

	}

	pcap_close(pcap);
}
