#include <time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>

#include "list.h"
#include "main.h"

struct udp_pkt {
	unsigned short len;
	unsigned char data[PKT_MAX];
};

struct udp_link {
	struct list_head item;
	unsigned int ip_src;
	unsigned int ip_des;
	time_t last_sec;
	unsigned short udp_src;
	unsigned short udp_des;
	unsigned short num;		/* how many packets saved */
	unsigned short reserved;
	struct udp_pkt pkt[SAVE_NUM];
};

static struct list_head g_udp_list[HASH_MAX];
static pthread_mutex_t g_udp_lock[HASH_MAX];

static void udp_timeout(int hash, time_t cur_s, int sec)
{
	struct udp_link *obj = NULL, *next = NULL;
	(void)pthread_mutex_lock(&g_udp_lock[hash]);
	list_for_each_entry_safe(obj, next, &g_udp_list[hash], item){
		if(cur_s - obj->last_sec > sec){
			unsigned char *p = (void *)&obj->ip_src;
			unsigned char *q = (void *)&obj->ip_des;
			printf("[-] UDP %u.%u.%u.%u:%d -> %u.%u.%u.%u:%d\n", p[0], p[1], p[2], p[3], ntohs(obj->udp_src),
					q[0], q[1], q[2], q[3], ntohs(obj->udp_des));

			list_del(&obj->item);
			free(obj);
		}
	}
	(void)pthread_mutex_unlock(&g_udp_lock[hash]);
}

void udp_check(struct ip *iph, struct udphdr *udph)
{
	struct udp_link *obj = NULL;
	int found = 0, hash = ((iph->ip_src.s_addr^iph->ip_dst.s_addr)^(udph->source^udph->dest))&(HASH_MAX-1);
	int payload_len = ntohs(iph->ip_len) - sizeof(struct ip) - sizeof(struct udphdr);

	unsigned char *p = (void *)&iph->ip_src.s_addr;
	unsigned char *q = (void *)&iph->ip_dst.s_addr;

	if(payload_len <= 0)
		return;

	(void)pthread_mutex_lock(&g_udp_lock[hash]);
	list_for_each_entry(obj, &g_udp_list[hash], item){
		if(iph->ip_src.s_addr == obj->ip_src && udph->source == obj->udp_src
				&& iph->ip_dst.s_addr == obj->ip_des && udph->dest == obj->udp_des) {
			found = 1;
			if(obj->num >= SAVE_NUM)
				break;
			obj->pkt[obj->num].len = (unsigned short)payload_len;
			memcpy(obj->pkt[obj->num++].data, (unsigned char *)udph+sizeof(struct udphdr), payload_len);
			break;
		}
	}

	if(found == 0){
		obj = calloc(sizeof(struct udp_link), 1);
		if(obj){
			obj->ip_src = iph->ip_src.s_addr;
			obj->ip_des = iph->ip_dst.s_addr;
			obj->udp_src = udph->source;
			obj->udp_des = udph->dest;
			obj->last_sec = time(NULL);
			list_add_tail(&obj->item, &g_udp_list[hash]);
			printf("[+] UDP %u.%u.%u.%u:%d -> %u.%u.%u.%u:%d\n", p[0], p[1], p[2], p[3], ntohs(udph->source),
					q[0], q[1], q[2], q[3], ntohs(udph->dest));
		}
	}

	(void)pthread_mutex_unlock(&g_udp_lock[hash]);
}

static void *thread_udp_timeout(void *arg)
{
	int i;
	(void)arg;
	(void)prctl(PR_SET_NAME, "udp_timeout");
	while(1){
		(void)sleep(5);
		for(i = 0; i < HASH_MAX; i++){
			udp_timeout(i, time(NULL), 15);
		}
	}
	return NULL;
}

int udp_init(void)
{
	int i = 0;
	pthread_t id;
	for(i = 0; i < HASH_MAX; i++){
		if(0 != pthread_mutex_init(&g_udp_lock[i], NULL))
			return -1;
		INIT_LIST_HEAD(&g_udp_list[i]);
	}

	if(0 != pthread_create(&id, NULL, thread_udp_timeout, NULL))
		return -1;
	return 0;
}

