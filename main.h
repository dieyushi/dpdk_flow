
#define TCP_FIN			0x01
#define TCP_SYN			0x02
#define TCP_RST			0x04
#define TCP_ACK			0x10
#define TCP_SACK		(TCP_SYN|TCP_ACK)

#define HASH_MAX		8192
#define TCP_LINKS		256
#define TCP_TIMEOUT		30
#define UDP_LINKS		256
#define UDP_TIMEOUT		30
#define SAVE_NUM		5
#define PKT_MAX			1500

void tcp_check(struct ip *iph, struct tcphdr *tcph);
void tcp_new(struct ip *iph, struct tcphdr *tcph, time_t cur_s);
void tcp_del(struct ip *iph, struct tcphdr *tcph);
int tcp_init(void);
int udp_init(void);
void udp_check(struct ip *iph, struct udphdr *udph);

