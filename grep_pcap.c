#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<pcap.h>
#include<time.h>
#include<netinet/if_ether.h>
#include<netinet/ether.h>
#include<netinet/in.h>
#include<arpa/inet.h>


int total=0;
int total_tcp=0;
int total_udp=0;
int total_other=0;
int no=0;
int num=0;
int num_of=0;
pcap_t *handle;
FILE *fp=NULL;

struct ip {
        u_char ip_vhl;      /* version << 4 | header length >> 2 */
        u_char ip_tos;      /* type of service */
        u_short ip_len;     /* total length */
        u_short ip_id;      /* identification */
        u_short ip_off;     /* fragment offset field */
    #define IP_RF 0x8000        /* reserved fragment flag */
    #define IP_DF 0x4000        /* dont fragment flag */
    #define IP_MF 0x2000        /* more fragments flag */
    #define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
        u_char ip_ttl;      /* time to live */
        u_char ip_p;        /* protocol */
        u_short ip_sum;     /* checksum */
        struct in_addr ip_src;
        struct in_addr ip_dst; /* source and dest address */

};


struct tcp {
        u_short th_sport;   /* source port */
	u_short th_dport;   /* destination port */
	u_int32_t th_seq;       /* sequence number */
	u_int32_t th_ack;       /* acknowledgement number */
};

void pcap_callback(u_char *arg,const struct pcap_pkthdr *header,const u_char *content){
	static int d=0;
//	const struct EtherHeader *eth;
	printf("No. %s",ctime((const time_t *)&header->ts.tv_sec));
//	eth=(EtherHeader *)arg;
	struct ether_header *eth=(struct ether_header *)content;
	//ether_type=ntohs()		
	printf("Des MAC: %s\n",ether_ntoa((struct ether_addr *)eth->ether_dhost));
	printf("Source MAC: %s\n",ether_ntoa((struct ether_addr *)eth->ether_shost));

//	int stop=total;
        if(num==total+no+1)
        	pcap_breakloop(handle);



	if(ntohs(eth->ether_type)==ETHERTYPE_IP){
//		int stop=total+no;
//		if(num==stop-1)
//			pcap_breakloop(handle);		
		total++;
		printf("IP\n");
		struct ip *ip = (struct ip*)(content + ETHER_HDR_LEN);
		char srcname[100];
                strcpy(srcname, inet_ntoa(ip->ip_src));
                char dstname[100];
                strcpy(dstname, inet_ntoa(ip->ip_dst));
                printf("src address: %s dest address: %s \n", srcname, dstname);

		if(num_of==total+no+1){
			fp=fopen("pcap.txt","w");
			fprintf(fp,"No. %s",ctime((const time_t *)&header->ts.tv_sec));
			fprintf(fp,"Des MAC: %s\n",ether_ntoa((struct ether_addr *)eth->ether_dhost));
			fprintf(fp,"Source MAC: %s\n",ether_ntoa((struct ether_addr *)eth->ether_shost));
			fprintf(fp,"src address: %s dest address: %s \n", srcname, dstname);
		}

	    	if (ip->ip_p == 6 /* tcp protocol number */) {
			total_tcp++;
			printf("TCP\n");
        		struct tcp *tcp = (struct tcp *)(content + ETHER_HDR_LEN + sizeof(ip));

        		u_short srcport = ntohs(tcp->th_sport);
        		u_short dstport = ntohs(tcp->th_dport);
        		printf("src port: %d dest port: %d \n", srcport, dstport);
			if(num_of==total+no+1){
				fprintf(fp,"TCP\n");
				fprintf(fp,"src port: %d dest port: %d \n\n\n", srcport, dstport);
				fclose(fp);
			}

    		}       

		else if (ip->ip_p == 17 /* udp protocol number */) {
			total_udp++;
                        printf("UDP\n");
                        struct tcp *tcp = (struct tcp*)(content + ETHER_HDR_LEN + sizeof(ip));

                        u_short srcport = ntohs(tcp->th_sport);
                        u_short dstport = ntohs(tcp->th_dport);
                        printf("src port: %d dest port: %d \n", srcport, dstport);
			if(num_of==total+no+1){
				fprintf(fp,"UDP\n");
                                fprintf(fp,"src port: %d dest port: %d \n\n\n", srcport, dstport);
                        	fclose(fp);
			}

		}

		else{
			total_other++;
			printf("other:%d\n",ip->ip_p);

		}
		

	}
	else{
		no++; 
		printf("No\n");
	}

	printf("\n\n");

}



int main(int argc, char *argv[]){

	char buf[1000];
//	int num=0;
		
	handle=pcap_open_offline(argv[2],buf);
	if(!handle){
		printf("pcap_opeen_offline():%s\n",buf);
		exit(1);
	}
	if(argc==5)
		num_of=atoi(argv[4]);
	if(argc==4||argc==5)
		num=atoi(argv[3]);
	if(-1==pcap_loop(handle,-1,pcap_callback,NULL)){
        	printf("pcap_loop:%s\n",pcap_geterr(handle));
        }
		
	printf("total IP package :%d\n",total);
	printf("total tcp :%d\n",total_tcp);
	printf("total udp :%d\n",total_udp);
	printf("total other protocal :%d\n",total_other);
	printf("not IP package :%d\n",no);
//	printf("%d",num);

	
//	printf("Open%d\n",handle->tzoff);


	//while(1){
	//	struct pcap_pkthdr *header=NULL;
		




return 0;
}

