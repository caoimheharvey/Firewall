#define PROTOCOL_TCP 6
#define PROTOCOL_UDP 17
#define PROTOCOL_SMTP 25
#define PROTOCOL_HTTPS 443
#define ONE 1
#define ZERO 0

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <asm/uaccess.h>

#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>

MODULE_LICENSE("GPL");				// Set the license
MODULE_AUTHOR("Eryk Szlachetka, Pamela Sabio"); // Set the Authors
MODULE_DESCRIPTION("Desc goes here");		// Set the description

unsigned int port_str_to_int(char *);
unsigned int ip_str_to_hl(char *);
void drop_all_packets(void);

/* Firewall policy struct */
struct mf_rule_desp {
	unsigned char in_out;
    	char *src_ip, *src_netmask, *src_port, *dest_ip, *dest_netmask, *dest_port;
	unsigned char proto;
	unsigned char action;
};

/* Firewall policy struct */

struct mf_rule {
	unsigned char in_out;       // 0 = Neither IN nor OUT, 1 = IN, 2 = OUT
	unsigned int src_ip;       
	unsigned int src_netmask;   
	unsigned int src_port;
	unsigned int dest_ip;

	unsigned int dest_netmask;
	unsigned int dest_port;
	unsigned char proto;        // 0 =  all, 1 = TCP, 2 = UDP
	unsigned char action;       // 0 = BLOCK, 1 = UNBLOCK
	struct list_head list;
};

static struct mf_rule policy_list;
static struct nf_hook_ops nfho_in;
static struct nf_hook_ops nfho_out;
//static struct nf_hook_ops nfho_in, nfho_out;   // Struct holding set of hook function options
static unsigned char *ip = "\xC0\xA8\x00\x01"; // Ip in network byte order (192.168.0.1);
static char *interface = "lo";                 // Loop-back interface which will be blocked
unsigned char *telnet_port = "x00\x17";	       // The telnet port
struct udphdr *udp_header, *udp_header_out;
struct sk_buff *sk_buffer_in, *sk_buffer_out;
struct iphdr *ip_header, *ip_header_out;
struct tcphdr *tcp_header, *tcp_header_out;
//struct httphdr *http_header_in, *http_header_out;
//struct smpthdr *smtp_header_in, *smtp_header_out;


unsigned int port_str_to_int(char *port_str) {
	unsigned int port = 0;
	int i = 0;

	if (port_str==NULL) {
		return 0;
	}

	while (port_str[i]!=' ') {
		port = port*10 + (port_str[i]-'0');
		++i;
	}

	return port;
}

unsigned int ip_str_to_hl(char *ip_str) {

	/* Convert the STRING to BYTE ARRAY first, e.g.: from "122.111.195.3" to [122][111][195][3]*/
	unsigned char ip_array[4];
	int i = 0;
	unsigned int ip = 0;

	if (ip_str==NULL) {
		return 0; 
	}

	memset(ip_array, 0, 4);

	while (ip_str[i]!='.') {
		ip_array[0] = ip_array[0]*10 + (ip_str[i++]-'0');
	}

	++i;

	while (ip_str[i]!='.') {
		ip_array[1] = ip_array[1]*10 + (ip_str[i++]-'0');
	}

	++i;

	while (ip_str[i]!='.') {
		ip_array[2] = ip_array[2]*10 + (ip_str[i++]-'0');
	}

	++i;

	while (ip_str[i]!=' ') {
		ip_array[3] = ip_array[3]*10 + (ip_str[i++]-'0');
	}

	/* Convert from BYTE ARRAY to HOST LONG INT format */
	ip = (ip_array[0] << 24);
	ip = (ip | (ip_array[1] << 16));
	ip = (ip | (ip_array[2] << 8));
	ip = (ip | ip_array[3]);
	return ip;

}


// Hook function for incoming packets.
unsigned int hook_func_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){	
	struct list_head *lh;
	struct mf_rule *rule;
	unsigned int source_ip;
	unsigned int destination_ip;
	unsigned int source_port, destination_port = 0;
	unsigned char *user_data;
	int i = 0;

	// Check if we are dealing with loop-back interface is so then drop it.
  	if(strcmp(state->in->name,interface) == 0){
		return NF_DROP;
  	}
	
	if(!(skb)) { return NF_ACCEPT; } // Validate socket_buff
	ip_header= (struct iphdr *)skb_network_header(skb); // Assign the ip_header
	if(!(ip_header)){return NF_ACCEPT;} // Validate IP Packet
	if(ip_header->saddr == *(unsigned int *)ip){return NF_DROP;} // Compare IP  

	//Initialize variables
	source_ip = (unsigned int)ip_header->saddr;
	destination_ip = (unsigned int)ip_header->daddr;

	if (ip_header->protocol == PROTOCOL_UDP){
		printk(KERN_INFO "UDP Packet\n");
		udp_header = (struct udphdr *)(skb_transport_header(skb) + 20); // Assign header
		// Drop - if telnet
		if((udp_header->dest) == *(unsigned short*)telnet_port){ return NF_DROP;}
		// Assign ports
		source_port = (unsigned int)ntohs(udp_header->source);
		destination_port = (unsigned int)ntohs(udp_header->dest);
	}else if (ip_header->protocol == PROTOCOL_TCP) // Check if it is TCP protocol
	{
		printk(KERN_INFO "TCP Packet\n");
		tcp_header = (struct tcphdr *)(skb_transport_header(skb)+20); // Assign header
		// Assign ports
		source_port = (unsigned int)ntohs(tcp_header->source);
		destination_port = (unsigned int)ntohs(tcp_header->dest);
	}
	

	list_for_each(lh,&policy_list.list){
		i++;
		rule = list_entry(lh, struct mf_rule, list);
		
		// Check if we are working with "in" packet
		if(rule -> in_out != 1){
			continue; // Skip it
		}else{
			// Compare rule and the ip_header
			if((rule -> proto == ONE) && (ip_header->protocol == PROTOCOL_TCP)){
				// We are inside TCP (rule allows tcp, and the packet is tcp)
				// Check if action == 1 (Means check if action == ALLOW)
				if(rule -> action == 1){
					// Check if we are dealing with port 80
					if(source_port == 80){
						printk(KERN_INFO "\n\nPORT 80!\n\n");
					}else{
						printk(KERN_INFO "\n\nNOT PORT 80: S: %u | D: %u \n\n", source_port, destination_port);
					}

					user_data = (unsigned char *) ((unsigned char*) tcp_header_out + (tcp_header_out->doff *4));
					if((user_data[0] = 'H') && (user_data[1] == 'T') && (user_data[2] == 'T') && (user_data[3] == 'P')){
						printk(KERN_INFO "\n\nHTTP DATA!\n\n");
						return NF_ACCEPT; // Accept the packet if its HTTP
					}else{
						printk(KERN_INFO "\n\nNOT HTTP! %c,%c,%c,%c \n\n", user_data[0], user_data[1], user_data[2], user_data[3]);
					}
				}
			}else if(((rule -> proto==2) && (ip_header->protocol != PROTOCOL_UDP))){
				continue;
			}
		}
		//TODO: Check if in rule, if not skip
		//TODO: If in, compare protocols
		// i.e. rule protocol with packet protocol
		// e.g. (Rule) TCP == TCP (Packet)
		// if TCP check ACTION status
		// if status is to allow packet, then check if http/s port
		// if http/s port, check if http/s header
		// if http/s header - accept
		// Consider doing the same for SMTP
		// Drop all the rest
		
	}

	return NF_DROP;

}

// Hook for outgoing packets.
unsigned int hook_func_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	struct list_head *lh;
	struct mf_rule *rule;	
	// Local variables for ip addresses, ports and data.
	unsigned int destination_ip;
	unsigned int source_ip;
	unsigned int destination_port, source_port = 0;
	//unsigned char *user_data;
	int i = 0;

	// TODO: REMOVE THIS LINE OF CODE
	//return NF_ACCEPT;

	if(strcmp(state->in->name, interface) == 0){
		return NF_DROP;
	}
	
	if(!(skb)) { return NF_DROP; } // Validate socket_buff
        ip_header_out = (struct iphdr *)skb_network_header(skb); // Assign$
        if(!(ip_header_out)){return NF_DROP;} // Validate IP Packet
        if(ip_header_out->saddr == *(unsigned int *)ip){return NF_DROP;} // Compare$
	// Initialize ips
	destination_ip = (unsigned int) ip_header_out -> daddr;
	source_ip = (unsigned int) ip_header_out -> saddr;

	printk(KERN_INFO "Outgoing packet.");

	// Check if we are dealing with UDP PACKET
        if (ip_header_out->protocol == PROTOCOL_UDP){
                printk(KERN_INFO "UDP Packet Out\n");
                udp_header_out = (struct udphdr *)(skb_transport_header(skb) + 20);
		source_port = (unsigned int)ntohs(udp_header_out->source);
		destination_port = (unsigned int)ntohs(udp_header_out ->dest);
    		// DROP THE TELNET CONNECTIONS
                if((udp_header_out->dest) == *(unsigned short*)telnet_port){ return NF_DROP;}
        }else if (ip_header_out->protocol == PROTOCOL_TCP) // Check if we are dealing with TCP PACKET 
        {
                printk(KERN_INFO "TCP Packet Out\n");
                tcp_header_out = (struct tcphdr *)(skb_transport_header(skb)+20);
              	source_port = (unsigned int)ntohs(tcp_header_out->source);
		destination_port = (unsigned int)ntohs(tcp_header_out ->dest);
        }

	list_for_each(lh,&policy_list.list){
		i++;
		rule = list_entry(lh, struct mf_rule, list);
		//TODO: Check if out rule, if not skip
		//TODO: If out, compare protocols
		// i.e. rule protocol with packet protocol
		// e.g. (Rule) TCP == TCP (Packet)
		// if TCP check ACTION status
		// if status is to allow packet, then check if http/s port
		// if http/s port, check if http/s header
		// if http/s header - accept
		// Consider doing the same for SMTP
		// Drop all the rest
		
	}

        printk(KERN_INFO "Returning drop.");
        
	return NF_DROP; // If packets weren't accept so far, that means we can drop it.
	
}

void add_rule(struct mf_rule_desp * rule_desp_struct){
	struct mf_rule *rule;
	rule = kmalloc(sizeof(*rule), GFP_KERNEL);
	
	if (rule == NULL) {
		printk(KERN_INFO "ERROR ! MEMORY ALLOCATION FAILED !");
		return;
	}

	printk(KERN_INFO "Adding rule.");
	rule->in_out = rule_desp_struct->in_out;
	rule->src_ip = ip_str_to_hl(rule_desp_struct->src_ip);
	rule->src_netmask = ip_str_to_hl(rule_desp_struct->src_netmask);
	rule->src_port = port_str_to_int(rule_desp_struct->src_port);
	rule->dest_ip = ip_str_to_hl(rule_desp_struct->dest_ip);
	rule->dest_netmask = ip_str_to_hl(rule_desp_struct->dest_netmask);
	rule->dest_port = port_str_to_int(rule_desp_struct->dest_port);
	rule->proto = rule_desp_struct->proto;
	rule->action = rule_desp_struct->action;
	printk(KERN_INFO "Finished adding.\n");
	
	INIT_LIST_HEAD(&(rule->list));
	list_add_tail(&(rule->list), &(policy_list.list));
}

// Function to drop all the packets
void drop_all_packets(void){
	struct mf_rule_desp rule_block_all_incoming;
	struct mf_rule_desp rule_block_all_outgoing;
	
	printk(KERN_INFO "\n\nSetting the rules.\n\n");
	printk(KERN_INFO "Blocking incoming connections for all protocols.\n");
	rule_block_all_incoming.in_out = 1; // 0 = neither in or out, 1 = in, 2 = out
	rule_block_all_incoming.src_ip = (char *)kmalloc(16, GFP_KERNEL);
	strcpy(rule_block_all_incoming.src_ip, "10.0.2.15"); // TODO: CHANGE THE IP
	rule_block_all_incoming.src_netmask = (char *)kmalloc(16, GFP_KERNEL);
	strcpy(rule_block_all_incoming.src_netmask, "255.255.255.255");
	rule_block_all_incoming.src_port = NULL;
	rule_block_all_incoming.dest_ip = NULL;
	rule_block_all_incoming.dest_netmask = NULL;
	rule_block_all_incoming.dest_port = NULL;
	rule_block_all_incoming.proto = 0;  // ALL PROTOCOLS
	rule_block_all_incoming.action = 0; // BLOCK ACTION (DROP)
	add_rule(&rule_block_all_incoming);

	printk(KERN_INFO "Blocking outgoing connections for all protocols.\n");
	rule_block_all_outgoing.in_out = 2; // 0 = neither in or out, 1 = in, 2 = out
	rule_block_all_outgoing.src_ip = (char *)kmalloc(16, GFP_KERNEL);
	strcpy(rule_block_all_outgoing.src_ip, "10.0.2.15"); // TODO: CHANGE THE IP
	rule_block_all_outgoing.src_netmask = (char *)kmalloc(16, GFP_KERNEL);
	strcpy(rule_block_all_outgoing.src_netmask, "255.255.255.255");
	rule_block_all_outgoing.src_port = NULL;
	rule_block_all_outgoing.dest_ip = NULL;
	rule_block_all_outgoing.dest_netmask = NULL;
	rule_block_all_outgoing.dest_port = NULL;
	rule_block_all_outgoing.proto = 0;  // 0 all, 1 tcp, 2 udp
	rule_block_all_outgoing.action = 0; // 0 for block, 1 for unblock
	add_rule(&rule_block_all_outgoing);
	
}

//Called when module loaded using 'insmod'
int init_module()
{
	INIT_LIST_HEAD(&(policy_list.list));
	nfho_in.hook = hook_func_in;		//function to call when conditions below met
	nfho_in.hooknum = NF_INET_LOCAL_IN;	//called right after packet recieved, first hook in Netfilter
	nfho_in.pf = PF_INET;			//IPV4 packets
	nfho_in.priority = NF_IP_PRI_FIRST;	//set to highest priority over all other hook functions
	nf_register_hook(&nfho_in);		// Register the hook
	nfho_out.hook = hook_func_out;
	nfho_out.hooknum = NF_INET_LOCAL_OUT;
	nfho_out.pf = PF_INET;
	nfho_out.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho_out);
	drop_all_packets();
 	return 0;
}

//Called when module unloaded using 'rmmod'
void cleanup_module()
{
  	struct list_head *p, *q;
	struct mf_rule *a_rule;

	nf_unregister_hook(&nfho_in);
	nf_unregister_hook(&nfho_out);

	list_for_each_safe(p, q, &policy_list.list) {
		a_rule = list_entry(p, struct mf_rule, list);
		list_del(p);
		kfree(a_rule);
	}
}
