#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "utilities.h"

int debug = 0;

char* interface = NULL;

void* MallocZ (int nbytes){
    char *ptr = malloc(nbytes);  // use the real routine
    if (ptr == NULL)
	{
	    perror ("MallocZ failed, fatal\n");
	    exit (66);
	}

	// initialize the space to all zeroes
    memset (ptr, '\00', nbytes);

    return (ptr);
}

void checkOptions(const int argc, char* argv[])
{
    if (argc != 1) // options selected - must at least specify interface
    {
        for (int i = 1; i < argc; ++i)
        {
            if (strcmp(argv[i], "-i") == 0) // define interface
            {
                if (interface != NULL || i + 1 >= argc) // Reset or no interface specified
                {
                    printUsage(argv[0]);
                }
                interface = MallocZ(sizeof(argv[i + 1] + 1)); // + 1 for null termination
                strcpy(interface, argv[i + 1]);
                ++i; // Skip assigned interface
            }
            else if (strcmp(argv[i], "-d") == 0) // enable debugging
            {
                if (debug == 1) // Cannot set multiple times
                {
                    printUsage(argv[0]);
                }
                debug = 1;
            }
            else if (strcmp(argv[i], "-h") == 0) // help
            {
                printHelp();
            }
            else // invalid option, print usage
            {
                printUsage(argv[0]);
            }
        }
    }
    else
    {
        printUsage(argv[0]);
    }

    checkInterface(interface);

    if (debug == 1)
    {
        fprintf(stdout, "debug enabled\n");
        fprintf(stdout, "interface: %s\n", interface);
    }
}

int main(int argc, char *argv[])
{
    checkOptions(argc, argv);

    char *remote_host = NULL;
    struct sockaddr_in sin;	/* an Internet endpoint address */
    char buf[128];		    /* buffer for sending */
    time_t tbuf; 		    /* buffer for reading */
    int s;			        /* socket descriptor */

    

    remote_host = argv[1];

    /* Allocate a socket */
    s = socket(PF_INET,		    /* Internet Protocol Family */
            SOCK_DGRAM,	        /* Datagram connection */
	        IPPROTO_UDP);	    /* ... specifically, UDP */
    if (s == -1) {
        perror("socket");
        exit(2);
    }
    /* connect to prime's time of day service */
    memset(&sin, 0, sizeof(sin)); /* erase address struct */
    sin.sin_family = AF_INET;	  /* Internet Address Family */
    sin.sin_port = htons(37);	  /* time port - RFC 868 */
    sin.sin_addr.s_addr = inet_addr(remote_host); 
    if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
        perror("connect");
        exit(2);
    }

    /* send an empty datagram as a request */
    sprintf(buf,"What time is it???");
    if (send(s,buf,strlen(buf)+1,0) == -1) {
        perror("send");
        exit(2);
    }

    /* read the time */
    if (read(s,&tbuf,sizeof(tbuf)) == -1) {
        perror("read");
        exit(2);
    }
    close(s);

    /* ... and print it out! */
    printf("The time on %s is 0x%08x\n", remote_host, (uint32_t)tbuf);

    exit(0);
}