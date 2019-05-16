#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>	/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>		//struct ip, IPPROTO
#include <netinet/tcp.h>	//struct tcphdr
#include <cstring>
#include <regex>

using namespace std;

bool block_chk = false;
char *block_site = nullptr;

class Iphdr {
	private:
		const struct ip *ip;
	public:
		Iphdr() { this->ip = nullptr; }
		Iphdr(u_char **packet) {
			this->ip = (const struct ip *)*packet;
			*packet += this->ip->ip_hl * 4;
		}
		~Iphdr() { this->ip = nullptr; }
		uint16_t getIplen() const { return ntohs(this->ip->ip_len); }
		uint8_t getIphl() const { return this->ip->ip_hl; }
		uint8_t getIpproto() const { return this->ip->ip_p; }
};

class Tcphdr {
	private:
		const struct tcphdr *tcp;
	public:
		Tcphdr() { this->tcp = nullptr; }
		Tcphdr(u_char **packet) {
			this->tcp = (const struct tcphdr *)*packet;
			*packet += getThoff() * 4;
		}
		~Tcphdr() { this->tcp = nullptr; }
		uint16_t getThsport() const { return ntohs(this->tcp->th_sport); }
		uint16_t getThdport() const { return ntohs(this->tcp->th_dport); }
		uint8_t getThoff() const { return this->tcp->th_off; }
};

class Httphdr {
	private:
		const u_char *packet;
		uint8_t len;
		const char * const http_method[8] = {
			"CONNECT", "TRACE", "OPTIONS", "DELETE",
			"PUT", "HEAD", "POST", "GET"};
	public:
		Httphdr() { this->packet = nullptr; }
		Httphdr(const Iphdr *ip, const Tcphdr *tcp,  u_char **packet) {
			this->packet = *packet;
			this->len = ip->getIplen() - ip->getIphl() * 4 - tcp->getThoff() * 4;
		}
		~Httphdr() { this->packet = nullptr; }
		bool Ishttp(uint8_t src, uint8_t dst) {
			if((dst == 80) && this->len) return true;
			else return false;
		}
		void find() {
			bool http = false;
			int i = sizeof(http_method)/sizeof(http_method[0]);
			while(i--) {
				if(strncmp(http_method[i], (const char *)packet,
				strlen(http_method[i])) == 0) {
					http = true;
					break;
				}
			}
			if(http) {
				if(block_site != nullptr) {
					regex pattern("(Host:) ([^\r\n]+)");
					string str((char *)packet, len);
					smatch m;

					if(regex_search(str, m, pattern)) {
						for(size_t i = 0; i < m.size(); i++)
							printf("m[%d] : %s\n", i, m.str(i).c_str());
						char *result = (char *)m.str(2).c_str();
						if(strncmp(block_site, result, sizeof(result)) == 0)
							block_chk = true;
					}
				}
				//http dump
				extern void dump(unsigned char*, int);
				dump((u_char *)packet, len);
			}
		}
};

void dump(unsigned char* buf, int size) {
	int i;
	for(int i = 0; i < size; i++) {
		if (i % 16 == 0)
			printf("\n");
		printf("%02x ", buf[i]);
	}
}

/* returns packet id */
static uint32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	uint32_t mark, ifi, uid, gid;
	int ret;
	unsigned char *data, *secdata;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	if (nfq_get_uid(tb, &uid))
		printf("uid=%u ", uid);

	if (nfq_get_gid(tb, &gid))
		printf("gid=%u ", gid);

	ret = nfq_get_secctx(tb, &secdata);
	if (ret > 0)
		printf("secctx=\"%.*s\" ", ret, secdata);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
		printf("payload_len=%d ", ret);
		Iphdr *ip = new Iphdr(&data);
		if(ip->getIpproto() == IPPROTO_TCP) {
			Tcphdr *tcp = new Tcphdr(&data);
			Httphdr *http = new Httphdr(ip, tcp, &data);
			if(http->Ishttp(tcp->getThsport(), tcp->getThdport()))
				http->find();
			delete http;
			delete tcp;
		}
		delete ip;
	}
	fputc('\n', stdout);

	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	uint32_t id = print_pkt(nfa);
	printf("entering callback\n");
	if(block_chk) {
		block_chk = false;
		printf("blocked\n");
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
	else
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	uint32_t queue = 0;
	char buf[4096] __attribute__ ((aligned));

	switch(argc) {
		case 2 : block_site = argv[1]; break;
		case 1 : break;
		default : 
			fprintf(stderr, "Usage: %s <site address>\n", argv[0]);
			exit(EXIT_FAILURE);
			break;
	}

	/*
	if (argc == 2) {
		queue = atoi(argv[1]);
		if (queue > 65535) {
			fprintf(stderr, "Usage: %s [<0-65535>]\n", argv[0]);
			exit(EXIT_FAILURE);
		}
	}*/

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

	printf("binding this socket to queue '%d'\n", queue);
	qh = nfq_create_queue(h, queue, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	printf("setting flags to request UID and GID\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve process UID/GID.\n");
	}

	printf("setting flags to request security context\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve security context.\n");
	}

	printf("Waiting for packets...\n");

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
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
