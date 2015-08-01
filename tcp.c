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

struct tcp_pkt {
	unsigned short len;
	unsigned char data[PKT_MAX];
};

struct tcp_link {
	struct list_head item;
	unsigned int ip_src;
	unsigned int ip_des;
	unsigned int next_seq;
	unsigned int init_seq;
	time_t last_sec;
	unsigned short tcp_src;
	unsigned short tcp_des;
	unsigned short num;		/* how many packets saved */
	unsigned short reserved;
	struct tcp_pkt pkt[SAVE_NUM];
};

static struct list_head g_tcp_list[HASH_MAX];
static pthread_mutex_t g_tcp_lock[HASH_MAX];

static void tcp_timeout(int hash, time_t cur_s, int sec)
{
	struct tcp_link *obj = NULL, *next = NULL;
	(void)pthread_mutex_lock(&g_tcp_lock[hash]);
	list_for_each_entry_safe(obj, next, &g_tcp_list[hash], item){
		if(cur_s - obj->last_sec > sec){
			unsigned char *p = (void *)&obj->ip_src;
			unsigned char *q = (void *)&obj->ip_des;
			printf("[!] TCP %u.%u.%u.%u:%d -> %u.%u.%u.%u:%d\n", p[0], p[1], p[2], p[3], ntohs(obj->tcp_src),
					q[0], q[1], q[2], q[3], ntohs(obj->tcp_des));

			list_del(&obj->item);
			free(obj);
		}
	}
	(void)pthread_mutex_unlock(&g_tcp_lock[hash]);
}

void tcp_check(struct ip *iph, struct tcphdr *tcph)
{
	struct tcp_link *obj = NULL;
	int hash = ((iph->ip_src.s_addr^iph->ip_dst.s_addr)^(tcph->source^tcph->dest))&(HASH_MAX-1);
	int payload_len = ntohs(iph->ip_len) - sizeof(struct ip) - tcph->doff*4;

	if(payload_len <= 0)
		return;

	(void)pthread_mutex_lock(&g_tcp_lock[hash]);
	list_for_each_entry(obj, &g_tcp_list[hash], item){
		if(iph->ip_src.s_addr == obj->ip_src && tcph->source == obj->tcp_src
				&& iph->ip_dst.s_addr == obj->ip_des && tcph->dest == obj->tcp_des
				&& obj->next_seq == ntohl(tcph->seq)){
			obj->next_seq = ntohl(tcph->seq) + payload_len;
			if(obj->num >= SAVE_NUM)
				break;
			obj->pkt[obj->num].len = (unsigned short)payload_len;
			memcpy(obj->pkt[obj->num++].data, (unsigned char *)tcph+tcph->doff*4, payload_len);
			break;
		}
	}
	(void)pthread_mutex_unlock(&g_tcp_lock[hash]);
}

void tcp_new(struct ip *iph, struct tcphdr *tcph, time_t cur_s)
{
	unsigned char *p = (void *)&iph->ip_src.s_addr;
	unsigned char *q = (void *)&iph->ip_dst.s_addr;

	struct tcp_link *obj = NULL;
	int found = 0, hash = ((iph->ip_src.s_addr^iph->ip_dst.s_addr)^(tcph->source^tcph->dest))&(HASH_MAX-1);
	(void)pthread_mutex_lock(&g_tcp_lock[hash]);
	list_for_each_entry(obj, &g_tcp_list[hash], item){
		if(iph->ip_src.s_addr == obj->ip_src && tcph->source == obj->tcp_src
				&& iph->ip_dst.s_addr == obj->ip_des && tcph->dest == obj->tcp_des){
			found = 1;
			obj->last_sec = cur_s;
			break;
		}
	}

	if(found == 0){
		obj = calloc(sizeof(struct tcp_link), 1);
		if(obj){
			obj->ip_src = iph->ip_src.s_addr;
			obj->ip_des = iph->ip_dst.s_addr;
			obj->tcp_src = tcph->source;
			obj->tcp_des = tcph->dest;
			obj->last_sec = cur_s;
			obj->init_seq = ntohl(tcph->seq);
			obj->next_seq = obj->init_seq + 1;
			list_add_tail(&obj->item, &g_tcp_list[hash]);
			printf("[+] TCP %u.%u.%u.%u:%d -> %u.%u.%u.%u:%d\n", p[0], p[1], p[2], p[3], ntohs(tcph->source),
					q[0], q[1], q[2], q[3], ntohs(tcph->dest));
		}
	}
	(void)pthread_mutex_unlock(&g_tcp_lock[hash]);
}

void tcp_del(struct ip *iph, struct tcphdr *tcph)
{
	unsigned char *p = (void *)&iph->ip_src.s_addr;
	unsigned char *q = (void *)&iph->ip_dst.s_addr;

	struct tcp_link *obj = NULL, *next = NULL;
	int hash = ((iph->ip_src.s_addr^iph->ip_dst.s_addr)^(tcph->source^tcph->dest))&(HASH_MAX-1);
	(void)pthread_mutex_lock(&g_tcp_lock[hash]);
	list_for_each_entry_safe(obj, next, &g_tcp_list[hash], item){
		if(iph->ip_src.s_addr == obj->ip_src && tcph->source == obj->tcp_src
				&& iph->ip_dst.s_addr == obj->ip_des && tcph->dest == obj->tcp_des){
			printf("[-] TCP %u.%u.%u.%u:%d -> %u.%u.%u.%u:%d\n", p[0], p[1], p[2], p[3], ntohs(tcph->source),
					q[0], q[1], q[2], q[3], ntohs(tcph->dest));
			list_del(&obj->item);
			free(obj);
			break;
		}
	}
	(void)pthread_mutex_unlock(&g_tcp_lock[hash]);
}

static void *thread_tcp_timeout(void *arg)
{
	int i;
	(void)arg;
	(void)prctl(PR_SET_NAME, "tcp_timeout");
	while(1){
		(void)sleep(5);
		for(i = 0; i < HASH_MAX; i++){
			tcp_timeout(i, time(NULL), 30);
		}
	}
	return NULL;
}

int tcp_init(void)
{
	int i = 0;
	pthread_t id;
	for(i = 0; i < HASH_MAX; i++){
		if(0 != pthread_mutex_init(&g_tcp_lock[i], NULL))
			return -1;
		INIT_LIST_HEAD(&g_tcp_list[i]);
	}

	if(0 != pthread_create(&id, NULL, thread_tcp_timeout, NULL))
		return -1;
	return 0;
}

