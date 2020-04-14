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

int request = 1;

void sighandler(int signum)
{
    if(signum == SIGINT){
        request = 0;
    }
}
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
    if (argc != 2)
    {
        fprintf (stderr, "Invalid number of arguments");
        return 0;
    }

    /*
     *  if gethostbyname() is already an IPv4 address, then simply strcpy
     *  else, lookup the ip address, then strcpy
     */
    struct hostent *ht = gethostbyname(argv[1]);
    if ( ht != NULL )
    {
        strcpy(ip_addr, inet_ntoa(*(struct in_addr*)ht->h_addr));
        fprintf(stderr, "PING %s (%s)\n", argv[1], ip_addr);

    } else
    {
        herror("GET IP ADDRESS WRONG");
    }
    
    /*
     * Start to send non-stop request till SIGINT
     */
    int socketfd = 0;
    socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (socketfd < 0)
    {
        perror("ESTABLISHING SOCKET FAILED");
    }

    struct timeval timeout;
    struct timespec sent, received; //nanoseconds
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;    //microseconds
    
    //clock_gettime(CLOCK_MONOTONIC, &tp); This is for total time
    /*
     * Another discrepency. FreeBSD uses IPPROTO_IP while Linux uses SOL_IP
     */
    if (setsockopt(socketfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
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

    // struct sockaddr_in {
    //     sa_family_t    sin_family; /* address family: AF_INET */
    //     in_port_t      sin_port;   /* port in network byte order */
    //     struct in_addr sin_addr;   /* internet address */
    // };
    //On raw sockets sin_port is set to the IP protocol.
    
    struct sockaddr_in out_addr;
    struct sockaddr_in in_addr;
    out_addr.sin_addr.s_addr =(uint32_t)ht->h_addr;
    out_addr.sin_family = AF_INET;
    out_addr.sin_port = 0;

    int seqnum = 0;
    while(request)
    {
        /*
         * These are for Unix only. For Linux, use hdr.echo.id
         */
        struct icmp hdr;

        bzero(&hdr, sizeof(hdr));
        hdr.icmp_type = 8;
        hdr.icmp_hun.ih_idseq.icd_id = getpid();
        hdr.icmp_hun.ih_idseq.icd_seq = seqnum++;

        sleep(1);

        clock_gettime(CLOCK_MONOTONIC, &sent);
        if ( sendto(socketfd, &hdr, sizeof(hdr), 0, (struct sockaddr*)&out_addr, sizeof(out_addr)) == -1)
        {
            perror("SENDING FAILED");
        }

        socklen_t in_addr_len = sizeof(in_addr); 
        if (recvfrom(socketfd, &hdr, sizeof(hdr), 0, (struct sockaddr*)&in_addr, &in_addr_len) == -1)
        {
            perror("RECEIVING FAILED");
        }
        clock_gettime(CLOCK_MONOTONIC, &received);

        double time = (received.tv_nsec - sent.tv_nsec) / 1000000.0;
        fprintf(stderr, "%f ms", time);
    }
}