#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>

#define MAX_DOMAIN_LEN 80 // maximum length of domain
#define NUM_DOMAIN 1000000 // the maximum number of domains to block

char** domain; // domains to block
int num_domain; // the number of domains to block

void usage() {
    puts("syntax : 1m-block <site list file>");
    puts("sample : 1m-block top-1m.txt");
}

void store_domain(FILE* fp) { // sort domains in alphabetical order
	for (int i = 0; i < NUM_DOMAIN; i++) {
		char* buf = malloc(MAX_DOMAIN_LEN);
		fgets(buf, MAX_DOMAIN_LEN, fp);
		int len = strlen(buf);
		if (buf[len - 1] == '\n')
			buf[len - 1] = 0;
		buf = strchr(buf, ',') + 1;

		for (int j = num_domain - 1; ; j--) {
			if (j == -1 || strcmp(domain[j], buf) < 0) {
				domain[j + 1] = buf;
				break;
			}
			else
				domain[j + 1] = domain[j];
		}

		num_domain++;
		if (feof(fp)) break;
	}
}

int search_domain(int first, int last, char* target) { // binary search
	int mid = first + (last - first) / 2;
	int r = strncmp(domain[mid], target, strlen(domain[mid]));

	if (first == last && r != 0) {
		return -1;
	}
	
	if (r > 0)
		return search_domain(first, mid, target);
	else if (r < 0)
		return search_domain(mid + 1, last, target);
	else if (r == 0)
		return r;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *d)
{
	u_int32_t id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
	}

	ret = nfq_get_payload(nfa, &data);

	char* packet = malloc(ret);
	memcpy(packet, data, ret);

	// parse IP/TCP/HTTP header
    struct iphdr *ip_header = (struct iphdr *)packet;
    struct tcphdr *tcp_header = (struct tcphdr*)(ip_header + 1);
    char* http_header = (char*)(tcp_header + 1);

	// host check
    char* host = strstr(http_header, "Host: ");
	if (host != 0) {
		host += strlen("Host: ");
		
		if (!search_domain(0, num_domain - 1, host)) {
			puts("domain blocked.");
			return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		}
	}

	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        usage();
        return 0;
    }

	FILE* fp = fopen(argv[1], "r");
	if (!fp) {
		printf("%s open failed.\n", argv[1]);
		return 0;
	}

	domain = (char**)malloc(NUM_DOMAIN * sizeof(char*));
	store_domain(fp);
	for (int i = 0; i < num_domain; i++) {
		puts(domain[i]);
	}

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
