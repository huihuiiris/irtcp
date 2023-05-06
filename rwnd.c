#include <linux/hash.h>
#include <linux/hashtable.h>
#include <linux/timex.h>
#include "rwnd.h"

#define FLOW_HASH_BITS 10

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hui");
MODULE_DESCRIPTION("A simple example netfilter module.");
MODULE_VERSION("0.0.1");

DEFINE_HASHTABLE(flowtable, FLOW_HASH_BITS);

static u32 hashflow(struct flow *f)
{
  u32 hashv;
  hashv = hash_32((u32)f->local_ip, 32);
  hashv += hash_32((u32)f->local_port, 32);
  hashv += hash_32((u32)f->remote_ip, 32);
  hashv += hash_32((u32)f->remote_port, 32);
  hashv = hash_32(hashv, FLOW_HASH_BITS);
  return hashv;
}

static u8 flow_key_equals(struct flow *a, struct flow *b)
{
  if (NULL == a && NULL == b)
  {
    return 1;
  }
  else if (NULL == a || NULL == b)
  {
    return 0;
  }
  else if (a->local_ip != b->local_ip)
  {
    return 0;
  }
  else if (a->local_port != b->local_port)
  {
    return 0;
  }
  else if (a->remote_ip != b->remote_ip)
  {
    return 0;
  }
  else if (a->remote_port != b->remote_port)
  {
    return 0;
  }
  return 1;
}

static struct flow *flow_find(struct flow *f)
{
  struct flow *old_f;
  u32 key;
  key = hashflow(f);
  // printk(KERN_INFO "to find key is :%d \n", key);
  hash_for_each_possible(flowtable, old_f, node, key)
  {
    if (flow_key_equals(old_f, f))
    {
      return old_f;
    }
    // printk(KERN_INFO "same key different flow \n");
  }
  return NULL;
}

static int flow_opr(struct flow *f, u8 add)
{
  u32 key;
  struct flow *old_f;
  old_f = flow_find(f);
  if (old_f && (!add))
  {
    if (old_f->is_new == 2 && old_f->is_elephant)
    {
      if (flow_number > 0)
      {
        flow_number--;
      }
      printk(KERN_INFO "minus flow number is %d\n", flow_number);
    }
    hash_del(&old_f->node);
    kfree(old_f);
  }
  if (old_f && add)
  {
    return 0;
  }
  if (add)
  {
    key = hashflow(f);
    // printk(KERN_INFO "add key is :%d \n", key);
    hash_add(flowtable, &(f->node), key);
  }
  return 1;
}

static int flow_add(struct flow *f)
{
  return flow_opr(f, 1);
}

static int flow_del(struct flow *f)
{
  return flow_opr(f, 0);
}

#define DEC_UPDATE_PERIOD_SECOND 0.005
static struct timespec64 dec_update_period;
static struct timespec64 last_update;
static int timespec_inited = 0;
static unsigned short dec = 0;
static unsigned short dec_accu = 0;
static unsigned short accu_times = 0;

static int flow_update(struct flow *f)
{
  // 1 means not found.
  int update_code = 1;
  struct flow *old_f;

  old_f = flow_find(f);

  if (old_f)
  {
    if (old_f->is_new == 0 || old_f->is_new == 1) // client
    {

      old_f->rwnd = f->rwnd;

      kfree(f);
      return 0;
    }
    else if (old_f->is_new == 2) // server
    {
      // next for server
      old_f->ack_bytes += f->ack_bytes;
      if (old_f->ack_bytes > ELEPHANT_THRESHOLD && (!old_f->is_elephant))
      {
        old_f->is_elephant = true;
        printk(KERN_INFO "flow %08x:%d->%08x:%d , elephant : %d\n", old_f->local_ip, old_f->local_port, old_f->remote_ip, old_f->remote_port, old_f->is_elephant);
        flow_number++;
        unsigned bkt;
        struct flow *cur;

        int new_cwnd = credits / flow_number;
        old_f->rwnd = new_cwnd;
        hash_for_each(flowtable, bkt, cur, node)
        {
          if (cur->is_elephant)
          {
            cur->rwnd = new_cwnd;
            // cur->has_new = 1;
            cur->initwnd = new_cwnd;
            printk(KERN_INFO "server get new flow added  %08x:%d->%08x:%d , elephant : %d\n", cur->local_ip, cur->local_port, cur->remote_ip, cur->remote_port, cur->rwnd);
          }
        }
        // printk(KERN_INFO " add flow number is %d\n", flow_number);
      }
      memcpy(old_f->metalist, f->metalist, sizeof(struct int_md) * MAX_HOPS); // TODO free old_f->metalist???
      int i;

      unsigned short once_dec = 0;
      struct timespec64 current_time;
      struct timespec64 update_time;
      for (i = 0; i < MAX_HOPS; i++)
      {
        if (old_f->metalist[i].q_occupancy > 0)
        {
          once_dec += (old_f->metalist[i].q_occupancy);
        }
      }

      ktime_get_ts64(&current_time);
      if (0 == timespec_inited)
      {
        dec_update_period = ns_to_timespec64((s64)(DEC_UPDATE_PERIOD_SECOND * 1000000000));
        last_update = current_time;
        timespec_inited = 1;
      }

      update_time = timespec64_add(last_update, dec_update_period);
      if (timespec64_compare(&current_time, &update_time) >= 0)
      {
        // printk(KERN_INFO "Dec Update accu: %d times: %d\n", dec_accu, accu_times);
        dec = dec_accu / accu_times;
        dec_accu = once_dec;
        accu_times = 1;
        last_update = current_time;
      }
      else
      {
        dec = 0;
        dec_accu += once_dec;
        accu_times++;
      }

      // if (old_f->has_new == 1)
      // {
      //   old_f->rwnd = max((old_f->rwnd - dec), 1);
      //   printk(KERN_INFO " %08x:%d->%08x:%d, server new flow added :%d  \n", old_f->local_ip, old_f->local_port, old_f->remote_ip, old_f->remote_port, old_f->rwnd);
      // }
      // else
      // {

      // // printk(KERN_INFO " %08x:%d->%08x:%d, server calculate decrease win :%d ,queue is %d \n", old_f->local_ip, old_f->local_port, old_f->remote_ip, old_f->remote_port, old_f->rwnd,queue);
      if (dec > 0 && old_f->state == PC_AVOID)
      {
        // first change from avoid to recovery, record the current wnd and when recovery end, the snd is the recorded value
        old_f->recover_wnd = old_f->initwnd; //  old_f->recover_wnd = old_f->initwnd;
        old_f->state = PC_RECOVERY;
        // printk(KERN_INFO "client decrease snd win:%d \n", dec);
        old_f->rwnd = max(1, ((old_f->rwnd) - dec));
        old_f->tmp_wnd = old_f->rwnd;
        printk(KERN_INFO "%08x:%d->%08x:%d,client state 1 snd win:%d ,dec %d \n", old_f->local_ip, old_f->local_port, old_f->remote_ip, old_f->remote_port, old_f->rwnd, dec);
      }
      else if (dec > 0 && old_f->state == PC_RECOVERY)
      {
        // printk(KERN_INFO "client decrease snd win:%d \n", dec);
        old_f->rwnd = max(1, ((old_f->tmp_wnd) - dec));
        old_f->tmp_wnd = old_f->rwnd;
        printk(KERN_INFO "%08x:%d->%08x:%d,client state 2 snd win:%d ,dec %d\n", old_f->local_ip, old_f->local_port, old_f->remote_ip, old_f->remote_port, old_f->rwnd, dec);
      }
      else if (dec == 0 && old_f->state == PC_RECOVERY)
      {
        old_f->state = PC_AVOID;
        old_f->rwnd = max(1, old_f->recover_wnd);
        old_f->recover_wnd = 0;
        old_f->tmp_wnd = 0;
        printk(KERN_INFO "%08x:%d->%08x:%d,client state 3 snd win:%d \n", old_f->local_ip, old_f->local_port, old_f->remote_ip, old_f->remote_port, old_f->rwnd);
      }
      else if (dec == 0 && old_f->state == PC_AVOID)
      {
        old_f->rwnd = max(old_f->recover_wnd, old_f->rwnd);
        old_f->rwnd++;
        printk(KERN_INFO "%08x:%d->%08x:%d,client state 4 snd win:%d \n", old_f->local_ip, old_f->local_port, old_f->remote_ip, old_f->remote_port, old_f->rwnd);
      }

      // printk(KERN_INFO "%08x:%d->%08x:%d, server calculate decrease win:%d , dec is : %d, state is %d \n", old_f->local_ip, old_f->local_port, old_f->remote_ip, old_f->remote_port, old_f->rwnd, dec, old_f->state);
    }

    update_code = 0;
    // printk(KERN_INFO "update :%d \n", old_f->ack_bytes);
  }

  kfree(f);

  return update_code;
}

static struct flow *extract_inflow(struct iphdr *ip_header, struct tcphdr *tcp_header)
{
  // printk(KERN_INFO "begin to find flow\n");
  struct flow *f;
  f = (struct flow *)kcalloc(1, sizeof(struct flow), GFP_KERNEL);

  f->local_ip = ntohl(ip_header->saddr);
  f->remote_ip = ntohl(ip_header->daddr);
  f->local_port = ntohs(tcp_header->source);
  f->remote_port = ntohs(tcp_header->dest);
  f->ack_bytes = ntohs(ip_header->tot_len);

  f->is_elephant = false;

  f->initwnd = 0;
  f->rwnd = ntohs(tcp_header->window);

  f->scaleval = 0;
  memset(f->metalist, 0, sizeof(struct int_md) * MAX_HOPS);

  return f;
}
static struct flow *extract_outflow(struct iphdr *ip_header, struct tcphdr *tcp_header)
{
  // printk(KERN_INFO "begin to find flow\n");
  struct flow *f;
  f = (struct flow *)kcalloc(1, sizeof(struct flow), GFP_KERNEL);

  f->local_ip = ntohl(ip_header->daddr);
  f->remote_ip = ntohl(ip_header->saddr);
  f->local_port = ntohs(tcp_header->dest);
  f->remote_port = ntohs(tcp_header->source);
  return f;
}

void store_scale(struct flow *f, struct sk_buff *skb)
{
  struct tcp_options_received opt;
  tcp_clear_options(&opt);
  opt.wscale_ok = opt.rcv_wscale = 0;
  tcp_parse_options(skb, &opt, 0, NULL);
  if (opt.wscale_ok)
  {
    f->scaleval = opt.rcv_wscale;
  }
  else
  {
    f->scaleval = 0;
  }
}

static unsigned int hfunc_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct iphdr *iph = ip_hdr(skb);
  struct tcphdr *th;
  struct tcp_sock *tp;
  struct sock *sk = skb->sk;
  struct inet_connection_sock *icsk = inet_csk(sk);
  u16 oldwindow, newwindow;
  struct flow *f;
  if (!skb)
    return NF_ACCEPT;
  th = tcp_hdr(skb);
  if (ntohs(th->source) == 22 || ntohs(th->dest) == 22)
  {
    return NF_ACCEPT;
  }
  if (likely(iph->protocol == IPPROTO_TCP))
  {
    f = extract_outflow(iph, th);
    struct flow *old_f;
    old_f = flow_find(f);
    if (old_f == NULL)
    {
      return NF_ACCEPT;
    }

    // tore_scale(old_f, skb);
    //  if the packet is data packet,
    if (th->psh || th->ack)
    {
      tp = tcp_sk(sk);
      // for the first rtt
      if (old_f->is_new == 1)
      {
        tp->snd_cwnd = old_f->initwnd;
        // printk(KERN_INFO "%08x:%d->%08x:%d, client new init snd win:%d \n", ntohl(iph->saddr), ntohs(th->source), ntohl(iph->daddr), ntohs(th->dest), tp->snd_cwnd);
        old_f->is_new = 0;
      }
      else if (old_f->is_new == 0) // is_new = 0 means client
      {

        if (old_f->rwnd > 0)
        {
          // printk(KERN_INFO "%08x:%d->%08x:%d ,old tp->snd_cwnd:%d \n", ntohl(iph->saddr), ntohs(th->source), ntohl(iph->daddr), ntohs(th->dest), tp->snd_cwnd)

          tp->snd_cwnd = old_f->rwnd;
          // printk(KERN_INFO "%08x:%d->%08x:%d ,new snd win:%d \n", ntohl(iph->saddr), ntohs(th->source), ntohl(iph->daddr), ntohs(th->dest), tp->snd_cwnd);
        }
        return NF_ACCEPT;
      }
    }
    // if the packet is the SYN ACK sent out by the server, it need to recalculate the receive window to be the init window of the client
    if (th->syn && th->ack && (old_f->is_new == 2))
    {
      // if (old_f->scaleval > 0)
      // {
      //   newwindow = (old_f->initwnd * MSS) >> old_f->scaleval;
      // }
      // else
      // {
      //   newwindow = (old_f->initwnd) * MSS;
      // }
      // oldwindow = ntohs(th->window);
      // newwindow = MIN(oldwindow, newwindow);
      // printk(KERN_INFO "server before to network win:%d->%d \n", oldwindow, newwindow);
      oldwindow = htons(oldwindow);
      newwindow = htons(old_f->initwnd);
      th->window = newwindow;
      old_f->last_seq = th->ack_seq;
      inet_proto_csum_replace2(&th->check, skb, oldwindow, newwindow, 0);
      // printk(KERN_INFO " %08x:%d->%08x:%d ,init win calculated by server:%d->%d \n", ntohl(iph->saddr), ntohs(th->source), ntohl(iph->daddr), ntohs(th->dest), oldwindow, old_f->initwnd);
    }
    if (th->ack && (!th->syn) && (old_f->is_new == 2))
    {
      // oldwindow = ntohs(th->window);
      // if (old_f->scaleval > 0)
      // {
      //   newwindow = (old_f->initwnd * MSS) >> old_f->scaleval;
      // }
      // else
      // {
      //   newwindow = (old_f->initwnd) * MSS;
      // }
      // newwindow = MIN(oldwindow, newwindow);
      oldwindow = ntohs(th->window);
      newwindow = MIN(oldwindow, newwindow);
      newwindow = old_f->rwnd;

      // if (old_f->last_seq == th->ack_seq)
      // {
      //   newwindow = newwindow / 2;
      //   old_f->rwnd = old_f->rwnd / 2;
      //   printk(KERN_INFO " %08x:%d->%08x:%d ,retrans :%d \n", old_f->local_ip, old_f->local_port, old_f->remote_ip, old_f->remote_port, old_f->rwnd);
      // }
      old_f->last_seq = th->ack_seq;
      th->window = htons(newwindow);
      inet_proto_csum_replace2(&th->check, skb, oldwindow, newwindow, 0);
      // printk(KERN_INFO "server change win:%d->%d \n", oldwindow, newwindow);
    }

    if ((th->fin) || (th->rst))
    {
      printk(KERN_INFO "server send fin removed flow %08x:%d->%08x:%d, elephant: %d, f->is_new %d \n", old_f->local_ip, old_f->local_port, old_f->remote_ip, old_f->remote_port, old_f->is_elephant, old_f->is_new);
      int recal = old_f->is_elephant;
      flow_del(f);
      if (recal == 1 && flow_number >= 1)
      {

        u16 new_cwnd;
        unsigned bkt;
        new_cwnd = credits / flow_number;

        struct flow *cur;

        hash_for_each(flowtable, bkt, cur, node)
        {
          if (cur->is_elephant)
          {
            cur->rwnd = new_cwnd;
            cur->initwnd = new_cwnd;
            // cur->has_new = 1;
            printk(KERN_INFO "server send removed flow %08x:%d->%08x:%d , elephant : %d\n", cur->local_ip, cur->local_port, cur->remote_ip, cur->remote_port, cur->rwnd);
          }
        }
      }
    }
  }
  return NF_ACCEPT;
}

static unsigned int hfunc_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct iphdr *ip_header;
  struct udphdr *udp_header;
  struct vxlanhdr *vxh;
  struct int_shim_hdr *int_sh;
  struct int_md_hdr *int_md;
  unsigned char *int_metadata;
  int int_hdrs_size;
  int num_md_vals;
  int int_md_size;
  struct ethhdr *inner_ethh;
  struct iphdr *inner_iph;
  struct tcphdr *inner_th;

  struct int_md metalist[MAX_HOPS];
  struct int_md *meta;
  int i, j;
  int update_code;

  struct flow *f;

  memset(metalist, 0, sizeof(struct int_md) * MAX_HOPS);

  ip_header = ip_hdr(skb);
  if (ip_header->protocol != IPPROTO_UDP)
  {
    return NF_ACCEPT;
  }

  udp_header = (struct udphdr *)skb_transport_header(skb);
  // printk(KERN_INFO "Got UDP %d->%d\n", ntohs(udp_header->source), ntohs(udp_header->dest));

  if (ntohs(udp_header->dest) != VXLAN_PORT)
  {
    return NF_ACCEPT;
  }
  vxh = udp_header + 1;
  // printk(KERN_INFO "Got VxLAN %d\n", ntohl(vxh->vx_vni));

  if ((vxh->vx_flags & htonl(VXLAN_NEXT_PROTO_MSK)) != htonl(VXLAN_NEXT_PROTO_INT))
  {
    return NF_ACCEPT;
  }
  // printk(KERN_INFO "Decode int. \n");
  int_sh = (struct int_shim_hdr *)(vxh + 1);
  int_md = (struct int_md_hdr *)(int_sh + 1);
  int_metadata = (unsigned char *)(int_md + 1);
  num_md_vals = int_md->ins_cnt * int_md->total_hop_cnt;

  // int_hdrs_size = sizeof(struct int_shim_hdr) + sizeof(struct int_md_hdr) + (num_md_vals * sizeof(__be32));

  // Original L2 Frame
  // int outer_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct vxlanhdr) + int_hdrs_size;
  inner_ethh = (struct ethhdr *)(int_metadata + num_md_vals * sizeof(__be32));
  inner_iph = (struct iphdr *)(inner_ethh + 1); // IP  header structure
  if (inner_iph->protocol != IPPROTO_TCP)
  {
    // printk(KERN_INFO "Got inner IP protocol %d\n", inner_iph->protocol);
    return NF_ACCEPT;
  }

  // printk(KERN_INFO "Ins count %d, Hop count %d, Inst mask %d\n", int_md->ins_cnt, int_md->total_hop_cnt, int_md->inst_mask);

  // INT Metadata
  for (i = 0; i < int_md->total_hop_cnt; i++)
  {
    meta = metalist + i;
    j = 0;
    if (int_md->inst_mask & 128)
    {
      meta->switch_id = *(__be32 *)(int_metadata + (int_md->ins_cnt * i + j) * sizeof(__be32)) & htonl(0x7FFFFFFF);
      // printk(KERN_INFO "Switch ID %d\n", ntohl(meta->switch_id));
      j++;
    }
    if (int_md->inst_mask & 64)
    {
      meta->ingress_port_id = *(__be32 *)(int_metadata + (int_md->ins_cnt * i + j) * sizeof(__be32)) & htonl(0x7FFFFFFF);
      // printk(KERN_INFO "ingress_port_id %d\n", ntohl(meta->ingress_port_id));
      j++;
    }
    if (int_md->inst_mask & 32)
    {
      meta->hoplatency = ntohl(*(__be32 *)(int_metadata + (int_md->ins_cnt * i + j) * sizeof(__be32)) & htonl(0x7FFFFFFF));
      // printk(KERN_INFO "hop latency %d\n", ntohl(meta->hoplatency));
      j++;
    }
    if (int_md->inst_mask & 16)
    {
      meta->q_occupancy = ntohl(*(__be32 *)(int_metadata + (int_md->ins_cnt * i + j) * sizeof(__be32)) & htonl(0x00FFFFFF));

      j++;
    }
    if (int_md->inst_mask & 8)
    {
      meta->ingress_tstamp = ntohl(*(__be32 *)(int_metadata + (int_md->ins_cnt * i + j) * sizeof(__be32)) & htonl(0x7FFFFFFF));
      // printk(KERN_INFO "ingress time %d\n", ntohl(meta->ingress_tstamp));
      j++;
    }
    if (int_md->inst_mask & 4)
    {
      meta->egress_port_id = *(__be32 *)(int_metadata + (int_md->ins_cnt * i + j) * sizeof(__be32)) & htonl(0x7FFFFFFF);
      // printk(KERN_INFO "egress_port_id %d\n", ntohl(meta->egress_port_id));
      j++;
    }
    if (int_md->inst_mask & 2)
    {
      meta->q_congestion = *(__be32 *)(int_metadata + (int_md->ins_cnt * i + j) * sizeof(__be32)) & htonl(0x7FFFFFFF);
      // printk(KERN_INFO "congestion %d\n", ntohl(meta->q_congestion));
      j++;
    }
    if (int_md->inst_mask & 1)
    {
      meta->egress_port_tx_utilization = *(__be32 *)(int_metadata + (int_md->ins_cnt * i + j) * sizeof(__be32)) & htonl(0x7FFFFFFF);
      // printk(KERN_INFO "tx utilization %d\n", ntohl(meta->egress_port_tx_utilization));
      j++;
    }
  }

  inner_th = (struct tcphdr *)(((unsigned char *)inner_iph) + (inner_iph->ihl * 4));
  if (ntohs(inner_th->source) == 22 || ntohs(inner_th->dest) == 22)
  {
    return NF_ACCEPT;
  }

  // printk(KERN_INFO "Got inner %08x:%d->%08x:%d, ack num is : %d\n", ntohl(inner_iph->saddr), ntohs(inner_th->source), ntohl(inner_iph->daddr), ntohs(inner_th->dest),inner_th->ack_seq);
  f = extract_inflow(inner_iph, inner_th);

  memcpy(f->metalist, metalist, sizeof(struct int_md) * MAX_HOPS);

  //!!!!!! when server receive a new syn from client, the server should add it to flow table calculate the init_cwnd for this new flow
  if (inner_th->syn && (!inner_th->ack))
  {
    // printk(KERN_INFO "server Got inner SYN %08x:%d->%08x:%d\n", ntohl(inner_iph->saddr), ntohs(inner_th->source), ntohl(inner_iph->daddr), ntohs(inner_th->dest));
    if (flow_find(f))
    {
      return NF_ACCEPT;
    }
    // flow_number++;
    unsigned bkt;
    u16 new_cwnd;
    printk(KERN_INFO "flow number is %d\n", flow_number);
    if (flow_number == 0)
    {
      new_cwnd = credits;
    }
    else
    {
      new_cwnd = credits / flow_number;
    }

    f->initwnd = new_cwnd;
    f->rwnd = new_cwnd;
    f->is_new = 2; //~~~~~is_new = 2 means its server
    f->state = PC_AVOID;
    flow_add(f);

    printk(KERN_INFO "server Got inner SYN %08x:%d->%08x:%d, initwnd: %d\n", ntohl(inner_iph->saddr), ntohs(inner_th->source), ntohl(inner_iph->daddr), ntohs(inner_th->dest), new_cwnd);
  }
  if ((inner_th->fin) || (inner_th->rst))
  {
    printk(KERN_INFO "server fin removed flow %08x:%d->%08x:%d, elephant: %d, f->is_new %d \n", f->local_ip, f->local_port, f->remote_ip, f->remote_port, f->is_elephant, f->is_new);
    int recal = f->is_elephant;
    flow_del(f);
    if (recal == 1 && flow_number >= 1)
    {

      u16 new_cwnd;
      unsigned bkt;
      new_cwnd = credits / flow_number;

      struct flow *cur;

      hash_for_each(flowtable, bkt, cur, node)
      {
        if (cur->is_elephant)
        {
          cur->rwnd = new_cwnd;
          cur->initwnd = new_cwnd;
          // cur->has_new = 1;
          printk(KERN_INFO "server Got removed flow %08x:%d->%08x:%d , elephant : %d\n", cur->local_ip, cur->local_port, cur->remote_ip, cur->remote_port, cur->rwnd);
        }
      }
    }
  }
  if (inner_th->ack && (!inner_th->syn) && (!inner_th->fin))
  {

    f->rwnd = ntohs(inner_th->window);

    update_code = flow_update(f);
  }
  // when the client reveive the SYN ACK from the server, it record the init wnd from the TCP header, and add the new flow in the hash table
  if (inner_th->syn && inner_th->ack)
  {
    f->initwnd = ntohs(inner_th->window);
    f->is_new = 1;
    f->rwnd = 0;
    printk(KERN_INFO "client Got inner SYN + ACK %08x:%d->%08x:%d window is %d\n", ntohl(inner_iph->saddr), ntohs(inner_th->source), ntohl(inner_iph->daddr), ntohs(inner_th->dest), f->initwnd);
    flow_add(f);
  }
  return NF_ACCEPT;
}

int init_module()
{
  printk(KERN_CRIT "Module RWND init begin.\n");

  nfho_outgoing = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
  nfho_incoming = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

  /* Initialize netfilter hook */
  nfho_outgoing->hook = (nf_hookfn *)hfunc_out; /* hook function */
  nfho_outgoing->hooknum = NF_INET_LOCAL_OUT;   /* to send packets */
  nfho_outgoing->pf = PF_INET;                  /* IPv4 */
  nfho_outgoing->priority = NF_IP_PRI_FIRST;    /* max hook priority */

  nfho_incoming->hook = (nf_hookfn *)hfunc_in;  /* hook function */
  nfho_incoming->hooknum = NF_INET_PRE_ROUTING; /* to send packets */
  nfho_incoming->pf = PF_INET;                  /* IPv4 */
  nfho_incoming->priority = NF_IP_PRI_FIRST;    /* max hook priority */

  nf_register_hook(nfho_outgoing);
  nf_register_hook(nfho_incoming);

  // init_nic_list();

  printk(KERN_CRIT "Module RWND init finished.\n");

  return 0;
}

void cleanup_module()
{
  nf_unregister_hook(nfho_outgoing);
  nf_unregister_hook(nfho_incoming);
  kfree(nfho_outgoing);
  kfree(nfho_incoming);
  printk(KERN_CRIT "Module RWND Bye.\n");
}
