/*
 * MAC commands interface
 *
 * Copyright 2007-2012 Siemens AG
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Written by:
 * Sergey Lapin <slapin@ossfans.org>
 * Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Alexander Smirnov <alex.bluesman.smirnov@gmail.com>
 */
#include <linux/skbuff.h>
#include <linux/if_arp.h>

#include <net/ieee802154.h>
#include <net/ieee802154_netdev.h>
#include <net/wpan-phy.h>
#include <net/mac802154.h>
#include <net/nl802154.h>

#include "mac802154.h"

static int mac802154_cmd_assoc_req(struct sk_buff *skb)
{
	u8 cap;

	if (skb->len != 2)
		return -EINVAL;

	if (skb->pkt_type != PACKET_HOST)
		return 0;

	if (mac_cb(skb)->source.mode != IEEE802154_ADDR_LONG ||
	    mac_cb(skb)->source.pan_id != IEEE802154_PANID_BROADCAST)
		return -EINVAL;

	/*
	 * FIXME: check that we allow incoming ASSOC requests
	 * by consulting MIB
	 */

	cap = skb->data[1];

	return ieee802154_nl_assoc_indic(skb->dev, &mac_cb(skb)->source, cap);
}

static int mac802154_cmd_assoc_resp(struct sk_buff *skb)
{
	u8 status;
	u16 short_addr;

	if (skb->len != 4)
		return -EINVAL;

	if (skb->pkt_type != PACKET_HOST)
		return 0;

	if (mac_cb(skb)->source.mode != IEEE802154_ADDR_LONG ||
	    !(mac_cb(skb)->intrapan))
		return -EINVAL;

	/* FIXME: check that we requested association ? */

	status = skb->data[3];
	short_addr = skb->data[1] | (skb->data[2] << 8);
	pr_info("Received ASSOC-RESP status %x, addr %hx\n", status,
			short_addr);
	if (status) {
		mac802154_dev_set_short_addr(skb->dev,
				IEEE802154_ADDR_BROADCAST);
		mac802154_dev_set_pan_id(skb->dev,
				IEEE802154_PANID_BROADCAST);
	} else
		mac802154_dev_set_short_addr(skb->dev, short_addr);

	return ieee802154_nl_assoc_confirm(skb->dev, short_addr, status);
}

static int mac802154_cmd_disassoc_notify(struct sk_buff *skb)
{
	u8 reason;

	if (skb->len != 2)
		return -EINVAL;

	if (skb->pkt_type != PACKET_HOST)
		return 0;

	if (mac_cb(skb)->source.mode != IEEE802154_ADDR_LONG ||
	    (mac_cb(skb)->dest.mode != IEEE802154_ADDR_LONG &&
	     mac_cb(skb)->dest.mode != IEEE802154_ADDR_SHORT) ||
	    mac_cb(skb)->source.pan_id != mac_cb(skb)->dest.pan_id)
		return -EINVAL;

	reason = skb->data[1];

	/* FIXME: checks if this was our coordinator and the disassoc us */
	/* FIXME: if we device, one should receive ->da and not ->sa */
	/* FIXME: the status should also help */

	return ieee802154_nl_disassoc_indic(skb->dev, &mac_cb(skb)->source,
			reason);
}

static int mac802154_mlme_start_req(struct net_device *dev,
				    struct ieee802154_addr *addr,
				    u8 channel, u8 page,
				    u8 bcn_ord, u8 sf_ord,
				    u8 pan_coord, u8 blx,
				    u8 coord_realign)
{
	struct ieee802154_mlme_ops *ops = ieee802154_mlme_ops(dev);
	int rc = 0;
	struct mac802154_sub_if_data *priv = netdev_priv(dev);

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	spin_lock_bh(&priv->mib_lock);
	priv->indirect_send = pan_coord;
	spin_unlock_bh(&priv->mib_lock);

	BUG_ON(addr->mode != IEEE802154_ADDR_SHORT);

	mac802154_dev_set_pan_id(dev, addr->pan_id);
	mac802154_dev_set_short_addr(dev, addr->short_addr);
	mac802154_dev_set_ieee_addr(dev);
	mac802154_dev_set_page_channel(dev, page, channel);

	if (ops->llsec) {
		struct ieee802154_llsec_params params;
		int changed = 0;

		params.coord_shortaddr = addr->short_addr;
		changed |= IEEE802154_LLSEC_PARAM_COORD_SHORTADDR;

		params.pan_id = addr->pan_id;
		changed |= IEEE802154_LLSEC_PARAM_PAN_ID;

		params.hwaddr = ieee802154_devaddr_from_raw(dev->dev_addr);
		changed |= IEEE802154_LLSEC_PARAM_HWADDR;

		params.coord_hwaddr = params.hwaddr;
		changed |= IEEE802154_LLSEC_PARAM_COORD_HWADDR;

		rc = ops->llsec->set_params(dev, &params, changed);
	}

	/* FIXME: add validation for unused parameters to be sane
	 * for SoftMAC
	 */
	ieee802154_nl_start_confirm(dev, IEEE802154_SUCCESS);

	return rc;
}

static int mac802154_send_cmd(struct net_device *dev,
			      struct ieee802154_addr *addr, struct ieee802154_addr *saddr,
			      const u8 *buf, int len)
{
	struct sk_buff *skb;
	int err;
	BUG_ON(dev->type != ARPHRD_IEEE802154);
	skb = alloc_skb(LL_RESERVED_SPACE(dev) + len + dev->needed_tailroom,
			GFP_KERNEL);
	if (!skb)
		return -ENOMEM;
	skb_reserve(skb, LL_RESERVED_SPACE(dev));
	skb_reset_network_header(skb);
	mac_cb(skb)->type = IEEE802154_FC_TYPE_MAC_CMD;
	mac_cb(skb)->ackreq = true;

	err = dev_hard_header(skb, dev, ETH_P_IEEE802154, addr, saddr, len);
	if (err < 0) {
		kfree_skb(skb);
		return err;
	}
	skb_reset_mac_header(skb);
	memcpy(skb_put(skb, len), buf, len);
	skb->dev = dev;
	skb->protocol = htons(ETH_P_IEEE802154);
	return dev_queue_xmit(skb);
}


static int mac802154_send_empty(struct net_device *dev,
				struct ieee802154_addr *addr, struct ieee802154_addr *saddr)
{
	struct sk_buff *skb;
	int err;

	BUG_ON(dev->type != ARPHRD_IEEE802154);
	skb = alloc_skb(LL_RESERVED_SPACE(dev) + dev->needed_tailroom,
			GFP_KERNEL);
	if (!skb)
		return -ENOMEM;
	skb_reserve(skb, LL_RESERVED_SPACE(dev));
	skb_reset_network_header(skb);
	mac_cb(skb)->type = IEEE802154_FC_TYPE_DATA;
	mac_cb(skb)->ackreq = false;
	err = dev_hard_header(skb, dev, ETH_P_IEEE802154, addr, saddr, 0);
	if (err < 0) {
		kfree_skb(skb);
		return err;
	}
	skb_reset_mac_header(skb);
	skb->dev = dev;
	skb->protocol = htons(ETH_P_IEEE802154);
	return dev->netdev_ops->ndo_start_xmit(skb, dev);
}

static int mac802154_cmd_data_req(struct sk_buff *skb)
{
	struct mac802154_sub_if_data *priv = netdev_priv(skb->dev);
	struct list_head *pos, *head;
	struct pending_data_list *entry;

	if (mac_cb(skb)->source.mode != IEEE802154_ADDR_LONG)
		pr_debug("%s() from: %04X\n", __func__, mac_cb(skb)->source.short_addr);
	else
		pr_debug("%s() from: %016llX\n", __func__, mac_cb(skb)->source.extended_addr);

	priv->indirect_response = true;
	head = &priv->pending_list;
	list_for_each(pos, &priv->pending_list) {
		entry = list_entry(pos, struct pending_data_list, list);
		if (mac_cb(entry->data)->dest.short_addr == mac_cb(skb)->source.short_addr) {
			entry->data->sk = skb->sk;
			dev_queue_xmit(entry->data);
			return 0;
		}
	}

	pr_debug("%s() send empty ret %d\n", __func__, mac802154_send_empty(skb->dev, &mac_cb(skb)->source, &mac_cb(skb)->dest));

	return 0;
}


static int mac802154_mlme_assoc_req(struct net_device *dev,
				    struct ieee802154_addr *addr, u8 channel, u8 page, u8 cap)
{
	struct ieee802154_addr saddr;
	u8 buf[2];
	int pos = 0;
	saddr.mode = IEEE802154_ADDR_LONG;
	saddr.pan_id = IEEE802154_PANID_BROADCAST;
	saddr.extended_addr = ieee802154_devaddr_from_raw(dev->dev_addr);
/* FIXME: set PIB/MIB info */
	mac802154_dev_set_pan_id(dev, addr->pan_id);
	mac802154_dev_set_page_channel(dev, page, channel);
	mac802154_dev_set_ieee_addr(dev);
	buf[pos++] = IEEE802154_CMD_ASSOCIATION_REQ;
	buf[pos++] = cap;
	return mac802154_send_cmd(dev, addr, &saddr, buf, pos);
}

static int mac802154_mlme_assoc_resp(struct net_device *dev,
		struct ieee802154_addr *addr, u16 short_addr, u8 status)
{
	struct ieee802154_addr saddr;
	u8 buf[4];
	int pos = 0;

	saddr.mode = IEEE802154_ADDR_LONG;
	saddr.pan_id = addr->pan_id;
	saddr.extended_addr = ieee802154_devaddr_from_raw(dev->dev_addr);

	buf[pos++] = IEEE802154_CMD_ASSOCIATION_RESP;
	buf[pos++] = short_addr;
	buf[pos++] = short_addr >> 8;
	buf[pos++] = status;

	return mac802154_send_cmd(dev, addr, &saddr, buf, pos);
}

int mac802154_process_cmd(struct net_device *dev, struct sk_buff *skb)
{
	u8 cmd;

	if (skb->len < 1) {
		pr_warning("Uncomplete command frame!\n");
		goto drop;
	}

	cmd = *(skb->data);
	pr_debug("Command %02x on device %s\n", cmd, dev->name);

	switch (cmd) {
	case IEEE802154_CMD_ASSOCIATION_REQ:
		mac802154_cmd_assoc_req(skb);
		break;
	case IEEE802154_CMD_ASSOCIATION_RESP:
		mac802154_cmd_assoc_resp(skb);
		break;
	case IEEE802154_CMD_DISASSOCIATION_NOTIFY:
		mac802154_cmd_disassoc_notify(skb);
		break;
	case IEEE802154_CMD_DATA_REQ:
		mac802154_cmd_data_req(skb);
		break;
	default:
		pr_debug("Frame type is not supported yet\n");
		goto drop;
	}


	kfree_skb(skb);
	return NET_RX_SUCCESS;

drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

static int mac802154_mlme_poll_req(struct net_device *dev,
				   struct ieee802154_addr *addr)
{
	struct ieee802154_addr saddr;
	u8 buf[2];
	int pos = 0;
	saddr.mode = IEEE802154_ADDR_LONG;
	saddr.pan_id = IEEE802154_PANID_BROADCAST;
	saddr.extended_addr = ieee802154_devaddr_from_raw(dev->dev_addr);
	buf[pos++] = IEEE802154_CMD_DATA_REQ;
	return mac802154_send_cmd(dev, addr, &saddr, buf, pos);
}

static struct wpan_phy *mac802154_get_phy(const struct net_device *dev)
{
	struct mac802154_sub_if_data *priv = netdev_priv(dev);

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	return to_phy(get_device(&priv->hw->phy->dev));
}

static struct ieee802154_llsec_ops mac802154_llsec_ops = {
	.get_params = mac802154_get_params,
	.set_params = mac802154_set_params,
	.add_key = mac802154_add_key,
	.del_key = mac802154_del_key,
	.add_dev = mac802154_add_dev,
	.del_dev = mac802154_del_dev,
	.add_devkey = mac802154_add_devkey,
	.del_devkey = mac802154_del_devkey,
	.add_seclevel = mac802154_add_seclevel,
	.del_seclevel = mac802154_del_seclevel,
	.lock_table = mac802154_lock_table,
	.get_table = mac802154_get_table,
	.unlock_table = mac802154_unlock_table,
};

struct ieee802154_reduced_mlme_ops mac802154_mlme_reduced = {
	.get_phy = mac802154_get_phy,
};

struct ieee802154_mlme_ops mac802154_mlme_wpan = {
	.assoc_req = mac802154_mlme_assoc_req,
	.assoc_resp = mac802154_mlme_assoc_resp,
	.poll_req = mac802154_mlme_poll_req,
	.get_phy = mac802154_get_phy,
	.start_req = mac802154_mlme_start_req,
	.get_pan_id = mac802154_dev_get_pan_id,
	.get_short_addr = mac802154_dev_get_short_addr,
	.get_dsn = mac802154_dev_get_dsn,

	.llsec = &mac802154_llsec_ops,

	.set_mac_params = mac802154_set_mac_params,
	.get_mac_params = mac802154_get_mac_params,
};
