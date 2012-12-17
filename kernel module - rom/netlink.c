/**
 *\file  		netlink.c
 *@brief       	Netlink server implementation
 *@ingroup		NS
 *\authors     	Carsten.Vogel | Mohamad.Sbeiti \@paser.info
 *
 *\copyright   (C) 2012 Communication Networks Institute (CNI - Prof. Dr.-Ing. Christian Wietfeld)
 *                  at Technische Universitaet Dortmund, Germany
 *                  http://www.kn.e-technik.tu-dortmund.de/
 *
 *
 *              This program is free software; you can redistribute it
 *              and/or modify it under the terms of the GNU General Public
 *              License as published by the Free Software Foundation; either
 *              version 2 of the License, or (at your option) any later
 *              version.
 *              For further information see file COPYING
 *              in the top level directory
 ********************************************************************************
 * This work is part of the secure wireless mesh networks framework, which is currently under development by CNI
 ********************************************************************************/

#include <net/genetlink.h>
#include "rom.h"
#include<linux/time.h>
#include <linux/kfifo.h>

#ifdef limit_RLIFE

/**
 * \internal
 * @brief rl_head description
 */
struct rl_head {
	__be32			    dst_addr;  ///< IPv4 route address
	unsigned long       lastTime;
	struct kfifo		q_buf;	   ///< FIFO buffer (the queue)
	struct list_head	list;      ///< used for list linking
};

/** defines the queue list as struct list_head */
static LIST_HEAD(rl_list);
#endif

/**
 * \internal
 * @brief lb_head description
 */
struct lb_head {
	__be32			    dst_addr;  ///< IPv4 route address
    int                 count;
	unsigned long       lastTime;
	struct kfifo		q_buf;	   ///< FIFO buffer (the queue)
	struct list_head	list;      ///< used for list linking
};

/** defines the queue list as struct list_head */
static LIST_HEAD(lb_list);


/**
 *  @brief A sequence number counter is needed for sending netlink messages
 */
static u32 rom_seqnum = 1;

/**
 *   @brief ATTRIBUTES
 */
enum {
	ROM_A_UNSPEC,
	ROM_A_DST,
    ROM_A_MASK,
    ROM_A_ROUTE,
	ROM_A_GWSTATE,
	ROM_A_ERR_HOST,
	__ROM_A_MAX,
};

#define ROM_A_MAX (__ROM_A_MAX - 1)


/**
 * @brief ATTRIBUTE POLICY
 */
static struct nla_policy rom_genl_policy[ROM_A_MAX + 1] = {
	[ROM_A_DST] = { .type = NLA_U32 },
    [ROM_A_MASK] = { .type = NLA_U32 },
	[ROM_A_ERR_HOST] = { .type = NLA_U32 },
	[ROM_A_GWSTATE] = { .type = NLA_U8 },
};


/**
 * @brief FAMILY DEFINITION
 */
static struct genl_family rom_gnl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = "ROUTE-O-MATIC",
	.version = 1,
	.maxattr = ROM_A_MAX,
};

static struct genl_multicast_group rom_mc_grp = {
	.name = "rom-mc-grp",
};

/**
 *   @brief COMMANDS
 */
enum {
	ROM_C_UNSPEC,
	ROM_C_RREQ,		///< Route Request
    ROM_C_RLIFE, 	///< Route Lifetime
	ROM_C_RTADD,	///< Add Route
	ROM_C_RTDEL,	///< Delete Route
	ROM_C_RTDMP,	///< Dump Route Table
	ROM_C_QREL,		///< Queue Release
	ROM_C_QDMP,		///< Queue Dump
	ROM_C_SETGW,	///< Set gw_reachable state
	ROM_C_RERR,		///< Route Error (Link Layer Feedback)
	__ROM_C_MAX,
};

#define ROM_C_MAX (__ROM_C_MAX - 1)

/**
 *  @brief HANDLERS
 *  Route Request: broadcast RREQ message to user space
 *
 *  @param dst_addr destination address
 *
 *  @return ...
 */
int send_rom_rreq(__be32 dst_addr)
{
	struct sk_buff	*skb;
	void		*msg_head;
	int		rc;
	skb = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
//	skb = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb) {
		printk(KERN_WARNING "%s: RREQ generation error (genlmsg_new)\n",
								DEBUG_ID);
		return -ENOMEM;
	}
	/* create the message */
	msg_head = genlmsg_put(skb, 0, rom_seqnum++, &rom_gnl_family, 0,
								ROM_C_RREQ);
	if (msg_head == NULL) {
		printk(KERN_WARNING "%s: RREQ generation error (genlmsg_put)\n",
								DEBUG_ID);
		nlmsg_free(skb);
		return -ENOMEM;
	}

	rc = nla_put_u32(skb, ROM_A_DST, dst_addr);
	if (rc != 0) {
		printk(KERN_WARNING "%s: RREQ generation error (nla_put_u32)\n",
								DEBUG_ID);
		nlmsg_free(skb);
		return -EINVAL;
	}

	/* finalize the message */
	rc = genlmsg_end(skb, msg_head);
	if (rc < 0) {
		nlmsg_free(skb);
		return rc;
	}

	/* send the message */
	rc = genlmsg_multicast(skb, 0, rom_mc_grp.id, GFP_ATOMIC);
	//rc = genlmsg_multicast(skb, 0, rom_mc_grp.id, GFP_KERNEL);
	if (rc != 0) {
		printk(KERN_WARNING "%s: RREQ generation error (genlmsg_multicast returned %d) -  no user space client listening?)\n",
								DEBUG_ID,
								rc);
		return -EINVAL;
	}
	return 0;
}

/**
 *  @brief HANDLERS
 *  Route Lifetime: broadcast Route Lifetime(RLIFE) message to user space
 *
 *  @param dst_addr destination address
 *
 *  @return ...
 */
int send_rom_rlife(__be32 dst_addr)
{
	struct sk_buff	*skb;
	void		*msg_head;
	int		rc;

#ifdef limit_RLIFE
    unsigned long get_time;
    struct timeval tv;
    struct rl_head *rl_entry;
    bool found = false;

    do_gettimeofday(&tv);
    get_time = tv.tv_sec;
    list_for_each_entry(rl_entry, &rl_list, list) {
        if(rl_entry->dst_addr == dst_addr){
            if(rl_entry->lastTime == get_time){
                return 0;
            }
            else{
                found = true;
                rl_entry->lastTime = get_time;
                break;
            }
        }
    }
    if(!found){
        rl_entry = kmalloc(sizeof(*rl_entry), GFP_ATOMIC);
        rl_entry->dst_addr = dst_addr;
        rl_entry->lastTime = get_time;

        INIT_LIST_HEAD(&rl_entry->list);
        list_add(&(rl_entry->list), &rl_list);
    }
#endif

	skb = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
//	skb = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb) {
		printk(KERN_WARNING "%s: RLIFE generation error (genlmsg_new)\n",
								DEBUG_ID);
		return -ENOMEM;
	}
	/* create the message */
	msg_head = genlmsg_put(skb, 0, rom_seqnum++, &rom_gnl_family, 0,
								ROM_C_RLIFE);
	if (msg_head == NULL) {
		printk(KERN_WARNING "%s: RLIFE generation error (genlmsg_put)\n",
								DEBUG_ID);
		nlmsg_free(skb);
		return -ENOMEM;
	}

	rc = nla_put_u32(skb, ROM_A_ROUTE, dst_addr);
	if (rc != 0) {
		printk(KERN_WARNING "%s: RLIFE generation error (nla_put_u32)\n",
								DEBUG_ID);
		nlmsg_free(skb);
		return -EINVAL;
	}
	/* finalize the message */
	rc = genlmsg_end(skb, msg_head);
	if (rc < 0) {
		nlmsg_free(skb);
		return rc;
	}

	/* send the message */
	rc = genlmsg_multicast(skb, 0, rom_mc_grp.id, GFP_ATOMIC);
	//rc = genlmsg_multicast(skb, 0, rom_mc_grp.id, GFP_KERNEL);
	if (rc != 0) {
		printk(KERN_WARNING "%s: RLIFE generation error (genlmsg_multicast returned %d) -  no user space client listening?)\n",
								DEBUG_ID,
								rc);
		return -EINVAL;
	}
	return 0;
}

/**
 *  @brief Route Error: broadcast RERR message to user space (LLF)
 *
 *  TODO Code nearly identical to above send_rom_rreq() - write a wrapper
 *
 *  @param dst_addr
 *
 *  @return ...
 */
int send_rom_rerr(__be32 dst_addr)
{
	struct sk_buff	*skb;
	void		*msg_head;
	int		rc;

	if(LLFPerSecond >= 2){
		unsigned long get_time;
		struct timeval tv;
		struct lb_head *lb_entry;
		bool found = false;

		do_gettimeofday(&tv);
		get_time = tv.tv_sec;
		list_for_each_entry(lb_entry, &lb_list, list) {
		    if(lb_entry->dst_addr == dst_addr){
		        if(lb_entry->lastTime == get_time && lb_entry->count > LLFPerSecond){
		            found = true;
		            break;
		        }
		        else if(lb_entry->lastTime == get_time){
		            lb_entry->count++;
		            return 0;
		        }else{
		            lb_entry->lastTime = get_time;
		            lb_entry->count = 0;
		            return 0;
		        }
		    }
		}
		if(!found){
		    lb_entry = kmalloc(sizeof(*lb_entry), GFP_ATOMIC);
		    lb_entry->dst_addr = dst_addr;
		    lb_entry->lastTime = get_time;
		    lb_entry->count = 0;

		    INIT_LIST_HEAD(&lb_entry->list);
		    list_add(&(lb_entry->list), &lb_list);
		    return 0;
		}
	}

	skb = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	//skb = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb) {
		printk(KERN_WARNING "%s: RERR generation error (genlmsg_new)\n",
								DEBUG_ID);
		return -ENOMEM;
	}

	/* create the message */
	msg_head = genlmsg_put(skb, 0, rom_seqnum++, &rom_gnl_family, 0,
								ROM_C_RERR);
	if (msg_head == NULL) {
		printk(KERN_WARNING "%s: RERR generation error (genlmsg_put)\n",
								DEBUG_ID);
		nlmsg_free(skb);
		return -ENOMEM;
	}

	rc = nla_put_u32(skb, ROM_A_ERR_HOST, dst_addr);
	if (rc != 0) {
		printk(KERN_WARNING "%s: RERR generation error (nla_put_u32)\n",
								DEBUG_ID);
		nlmsg_free(skb);
		return -EINVAL;
	}
	/* finalize the message */
	rc = genlmsg_end(skb, msg_head);
	if (rc < 0) {
		nlmsg_free(skb);
		return rc;
	}

	/* send the message */
	rc = genlmsg_multicast(skb, 0, rom_mc_grp.id, GFP_ATOMIC);
//	rc = genlmsg_multicast(skb, 0, rom_mc_grp.id, GFP_KERNEL);
	if (rc != 0) {
		printk(KERN_WARNING "%s: RREQ generation error (genlmsg_multicast returned %d) -  no user space client listening?)\n",
								DEBUG_ID,
								rc);
		return -EINVAL;
	}
	return 0;
}

/**
 * @brief Add route: add destination to our route table
 *
 * @param skb socket buffer
 * @param info info
 *
 * @return ...
 */
static int rom_rtadd(struct sk_buff *skb, struct genl_info *info)
{
    struct t_id dest;

	if (!info->attrs[ROM_A_DST] || !info->attrs[ROM_A_MASK])
		return -1;

	dest.dst_addr = nla_get_u32(info->attrs[ROM_A_DST]);
	dest.dst_mask = nla_get_u32(info->attrs[ROM_A_MASK]);

	if (DEBUG_ROM)
		printk(KERN_INFO "%s: Received RTADD message for IP: %pI4, MASK: %pI4\n",
								DEBUG_ID, &dest.dst_addr, &dest.dst_mask);
	/* FIXME: possible race-condition here!? */
	release_queue_for_dst(dest);

	return add_route(dest);
}

/**
 * @brief Delete route: delete destination to our route table
 *
 * @param skb socket buffer
 * @param info info
 *
 * @return ...
 */
static int rom_rtdel(struct sk_buff *skb, struct genl_info *info)
{
    struct t_id dest;

	if (!info->attrs[ROM_A_DST] || !info->attrs[ROM_A_MASK])
		return -1;

	dest.dst_addr = nla_get_u32(info->attrs[ROM_A_DST]);
	dest.dst_mask = nla_get_u32(info->attrs[ROM_A_MASK]);
	if (DEBUG_ROM)
		printk(KERN_INFO "%s: Received RTDEL message for IP: %pI4, MASK: %pI4\n",
								DEBUG_ID, &dest.dst_addr, &dest.dst_mask);

	return delete_route(dest);
}

/**
 * @brief Route Table Dump: print out current route table
 *
 * @param skb socket buffer
 * @param info info
 *
 * @return 0
 */
static int rom_rtdmp(struct sk_buff *skb, struct genl_info *info)
{
	dump_route_table();
	return 0;
}

/**
 *  @brief Queue Release: dequeue all packets for destination
 *
 *  @param sbk socket buffer
 *  @param info info
 *
 *  @return -1 or 0
 */
static int rom_qrel(struct sk_buff *skb, struct genl_info *info)
{
	struct t_id dest;

	if (!info->attrs[ROM_A_DST] || !info->attrs[ROM_A_MASK])
		return -1;

	dest.dst_addr = nla_get_u32(info->attrs[ROM_A_DST]);
	dest.dst_mask = nla_get_u32(info->attrs[ROM_A_MASK]);

	if (DEBUG_ROM)
		printk(KERN_INFO "%s: Received QREL message for IP: %pI4, MASK: %pI4\n",
								DEBUG_ID, &dest.dst_addr, &dest.dst_mask);
	if (dest.dst_addr == 0)
		gw_reachable = 1;

	if (release_queue_for_dst(dest) != 0)
		return -1;

	return 0;
}

/**
 * @brief Queue Dump: print out current queue contents
 *
 * @param skb socket buffer
 * @param info info
 *
 * @return 0
 */
static int rom_qdmp(struct sk_buff *skb, struct genl_info *info)
{
	dump_queue_list();
	return 0;
}

/**
 *  @brief Set GW: set gw_reachable state
 *
 *  @param skb socket buffer
 *  @param info info
 *
 *  @return -1 or 0
 */
static int rom_setgw(struct sk_buff *skb, struct genl_info *info)
{
	int i = -1;

	if (info->attrs[ROM_A_GWSTATE]) {
		i = nla_get_u8(info->attrs[ROM_A_GWSTATE]);
		if (i == 0 || i == 1) {
			gw_reachable = i;
			return 0;
		}
	}

	return -1;
}

/**
 *  @brief OPERATION DEFINITIONS
 */
static struct genl_ops rom_gnl_ops_rtadd = {
	.cmd = ROM_C_RTADD,
	.flags = 0,
	.policy = rom_genl_policy,
	.doit = rom_rtadd,
	.dumpit = NULL,
};

/**
 *  @brief OPERATION DEFINITIONS
 */
static struct genl_ops rom_gnl_ops_rtdel = {
	.cmd = ROM_C_RTDEL,
	.flags = 0,
	.policy = rom_genl_policy,
	.doit = rom_rtdel,
	.dumpit = NULL,
};

/**
 *  @brief OPERATION DEFINITIONS
 */
static struct genl_ops rom_gnl_ops_rtdmp = {
	.cmd = ROM_C_RTDMP,
	.flags = 0,
	.policy = rom_genl_policy,
	.doit = rom_rtdmp,
	.dumpit = NULL,
};

/**
 *  @brief OPERATION DEFINITIONS
 */
static struct genl_ops rom_gnl_ops_qrel = {
	.cmd = ROM_C_QREL,
	.flags = 0,
	.policy = rom_genl_policy,
	.doit = rom_qrel,
	.dumpit = NULL,
};

/**
 *  @brief OPERATION DEFINITIONS
 */
static struct genl_ops rom_gnl_ops_qdmp = {
	.cmd = ROM_C_QDMP,
	.flags = 0,
	.policy = rom_genl_policy,
	.doit = rom_qdmp,
	.dumpit = NULL,
};

/**
 *  @brief OPERATION DEFINITIONS
 */
static struct genl_ops rom_gnl_ops_setgw = {
	.cmd = ROM_C_SETGW,
	.flags = 0,
	.policy = rom_genl_policy,
	.doit = rom_setgw,
	.dumpit = NULL,
};

/**
 * @brief netlink_init
 *
 * @return -1 or 0
 */
int netlink_init(void)
{
	if (genl_register_family(&rom_gnl_family) != 0) {
		printk(KERN_ALERT "%s: Could not register generic netlink family\n",
								DEBUG_ID);
		return -1;
	}

	if (genl_register_mc_group(&rom_gnl_family, &rom_mc_grp) != 0) {
		printk(KERN_ALERT "%s: Could not register generic netlink multicast group\n",
								DEBUG_ID);
		return -1;
	}

	if (genl_register_ops(&rom_gnl_family, &rom_gnl_ops_rtadd) != 0) {
		printk(KERN_ALERT "%s: Could not register generic netlink RTADD ops\n",
								DEBUG_ID);
		return -1;
	}

	if (genl_register_ops(&rom_gnl_family, &rom_gnl_ops_rtdel) != 0) {
		printk(KERN_ALERT "%s: Could not register generic netlink RTDEL ops\n",
								DEBUG_ID);
		return -1;
	}

	if (genl_register_ops(&rom_gnl_family, &rom_gnl_ops_rtdmp) != 0) {
		printk(KERN_ALERT "%s: Could not register generic netlink RTDMP ops\n",
								DEBUG_ID);
		return -1;
	}

	if (genl_register_ops(&rom_gnl_family, &rom_gnl_ops_qrel) != 0) {
		printk(KERN_ALERT "%s: Could not register generic netlink QREL ops\n",
								DEBUG_ID);
		return -1;
	}

	if (genl_register_ops(&rom_gnl_family, &rom_gnl_ops_qdmp) != 0) {
		printk(KERN_ALERT "%s: Could not register generic netlink QDMP ops\n",
								DEBUG_ID);
		return -1;
	}

	if (genl_register_ops(&rom_gnl_family, &rom_gnl_ops_setgw) != 0) {
		printk(KERN_ALERT "%s: Could not register generic netlink SETGW ops\n",
								DEBUG_ID);
		return -1;
	}

	return 0;
}

/**
 * @brief netlink_exit
 */
void netlink_exit(void)
{
    struct lb_head *lb_entry, *lb_next;
#ifdef limit_RLIFE
    struct rl_head *rl_entry, *rl_next;
    list_for_each_entry_safe(rl_entry, rl_next, &rl_list, list) {
        list_del(&rl_entry->list);
        kfree(rl_entry);
    }
#endif

    list_for_each_entry_safe(lb_entry, lb_next, &lb_list, list) {
        list_del(&lb_entry->list);
        kfree(lb_entry);
    }

	genl_unregister_ops(&rom_gnl_family, &rom_gnl_ops_setgw);
	genl_unregister_ops(&rom_gnl_family, &rom_gnl_ops_qrel);
	genl_unregister_ops(&rom_gnl_family, &rom_gnl_ops_qdmp);
	genl_unregister_ops(&rom_gnl_family, &rom_gnl_ops_rtdmp);
	genl_unregister_ops(&rom_gnl_family, &rom_gnl_ops_rtdel);
	genl_unregister_ops(&rom_gnl_family, &rom_gnl_ops_rtadd);
	genl_unregister_mc_group(&rom_gnl_family, &rom_mc_grp);
	genl_unregister_family(&rom_gnl_family);
}
