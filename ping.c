/*
 * Standard C includes
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <time.h>

/*
 * Standard UNIX includes
 */
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

/*
 * Other includes
 */
#include <netdb.h>
#include <sys/socket.h>
#include <sys/cdefs.h>
#include <sys/types.h>
#include <netinet/in_systm.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#define BUF_SIZE 500

int request = 1;

void sighandler(int signum)
{
    if(signum == SIGINT){
        request = 0;
    }
}

unsigned short checksum(void *hdr, int size)
{
    unsigned short *buf = hdr;
    unsigned int sum = 0;
    unsigned short result;

    for(sum = 0; size > 1; size -= 2){
        sum += *buf++;
    }
    if(size == 1){
        sum += *(unsigned char*)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result =~ sum;
    return result;
}

struct packet
{
    struct icmp hdr;
    char msg[64 - sizeof(struct icmp)];
    //the packet size is 64 bytes
};

int main(int argc, char **argv){

    /*
     * Waiting for user to trigger Ctrl-C
     */


    struct sigaction act;
    act.sa_handler = sighandler;
    sigaction(SIGINT, &act, NULL);

    char ip_addr[15];
    int ttl = 64;
    /*
     * Determine if command line argument is valid
     */
    if (argc == 3)
    {
        ttl = atoi(argv[2]);
    }

    /*
     *  if gethostbyname() is already an IPv4 address, then simply strcpy
     *  else, lookup the ip address, then strcpy
     */
    struct hostent *ht = gethostbyname(argv[1]);
    if (ht != NULL)
    {
        strcpy(ip_addr, inet_ntoa(*(struct in_addr*)ht->h_addr));
        fprintf(stderr, "PING %s (%s): 56 data bytes\n", argv[1], ip_addr);

    } else
    {
        herror("GET IP ADDRESS WRONG");
    }
    
    /*
     * Start to send non-stop request till SIGINT
     */
    int socketfd = 0;
    socketfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (socketfd < 0)
    {
        perror("ESTABLISHING SOCKET FAILED");
    }

    struct timeval timeout;
    struct timespec sent, received; //nanoseconds
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;    //microseconds
    
    //clock_gettime(CLOCK_MONOTONIC, &tp); This is for total time
    /*
     * Another discrepency. FreeBSD uses IPPROTO_IP while Linux uses SOL_IP
     */
    if (setsockopt(socketfd, IPPROTO_IP, IP_TTL, (const void*)&ttl, sizeof(ttl)) < 0)
    {
        perror("SETTING SOCKET OPTION FAILED");
        return 0;
    }
    /*
     * Set for timeout
     */ 
    if (setsockopt(socketfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0)
    {
        perror("SET TIMEOUT FAILED");
    }
    // /*
    //  * struct sockaddr_in {
    //  *   sa_family_t    sin_family; /* address family: AF_INET */
    //  *   in_port_t      sin_port;   /* port in network byte order */
    //  *   struct in_addr sin_addr;   /* internet address */
    //  * };
    //  *  On raw sockets sin_port is set to the IP protocol.
    //  */

    int sent_packet = 0, received_packet = 0;
    struct sockaddr_in out_addr;
    struct sockaddr_in in_addr;
    out_addr.sin_addr.s_addr =(uint32_t)ht->h_addr;
    out_addr.sin_family = AF_INET;
    out_addr.sin_port = htons(0);

    int flags = fcntl(socketfd, F_GETFL, 0);
    int r = fcntl(socketfd, F_SETFL, flags | O_NONBLOCK);
    if(r < 0){fprintf(stderr, "fcntl failed");}

    int seqnum = -1;
    double min = 500.0;
    double sum = 0.0;
    double max = 0.0;

    char buf[BUF_SIZE];

    while(request)
    {
        /*
         * These are for Unix only. For Linux, use struct icmphdr, hdr.echo.id
         * Checksum: the 16-bit one's complement of the one's complement sum of the packet. 
         * For IPv4, this is calculated from the ICMP message starting with the Type field
         */
        //struct icmp hdr;
        struct packet pac;
        bzero(&pac, sizeof(pac));
        pac.hdr.icmp_type = ICMP_ECHO;
        pac.hdr.icmp_hun.ih_idseq.icd_id = getpid();
        pac.hdr.icmp_hun.ih_idseq.icd_seq = seqnum++;
        pac.hdr.icmp_cksum = checksum(&pac, sizeof(pac));

        // for ( int i = 0; i < sizeof(pac.msg)-1; i++ ) 
        //     pac.msg[i] = i+'0'; 
        
        pac.msg[1] = 0;
        sleep(1);

        clock_gettime(CLOCK_MONOTONIC, &sent);
        if (sendto(socketfd, &pac, sizeof(pac), MSG_DONTWAIT, (struct sockaddr*)&out_addr, sizeof(out_addr)) == -1)
        {
            perror("SENDING FAILED");
        }else{
            sent_packet++;
        }

        socklen_t in_addr_len = sizeof(in_addr); 
        if (recvfrom(socketfd, buf , BUF_SIZE, MSG_DONTWAIT, (struct sockaddr*)&in_addr, &in_addr_len) == -1)
        {
            perror("\nRECEIVING FAILED");
        }else{
            received_packet++;
        }

        if(pac.hdr.icmp_type == 11)
        {
            if(pac.hdr.icmp_code == 0)
            {
                fprintf(stderr, "Code 0, Time Exceeded: Time-to-live exceeded in transit");
            }else if(pac.hdr.icmp_code == 1)
            {
                fprintf(stderr, "Code 1, Time Exceeded: Fragment reassembly time exceeded");
            }
        }

        clock_gettime(CLOCK_MONOTONIC, &received);

        double time = (received.tv_nsec - sent.tv_nsec) / 1000000.0 + (received.tv_sec - sent.tv_sec) * 1000.0;
        fprintf(stderr, "64 bytes from %s: icmp_seq = %d ttl = %d time = %.3f ms", ip_addr, seqnum, ttl, time);
        if ( time < min){
            min = time;
        }
        if ( time > max){
            max = time;
        }
        sum += time;
    }
    fprintf(stderr, "\n--- %s ping statistics ---\n", argv[1]);
    fprintf(stderr, "%d packets transmitted, %d packets received, %.2f%% packet loss\n", sent_packet, received_packet, 
                                                                        (sent_packet-received_packet)/sent_packet * 100.0);
    double average = sum / sent_packet;
    
    fprintf(stderr, "round-trip,on/min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms", min, average, max, (max-min)/4);
}