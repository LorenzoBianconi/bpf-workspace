#include <uapi/linux/bpf.h>
#include <asm/byteorder.h>

#include "bpf_helpers.h"

#define ETH_ALEN			6
#define IEEE80211_FCTL_FTYPE		0x000c

#define MT_DMA_HDR_LEN			4
struct mt76x02_rxwi {
	__le32 rxinfo;

	__le32 ctl;

	__le16 tid_sn;
	__le16 rate;

	u8 rssi[4];

	__le32 bbp_rxinfo[4];
};

struct ieee80211_hdr {
	__le16 frame_control;
	__le16 duration_id;
	u8 addr1[ETH_ALEN];
	u8 addr2[ETH_ALEN];
	u8 addr3[ETH_ALEN];
	__le16 seq_ctrl;
	u8 addr4[ETH_ALEN];
};

struct bpf_map_def SEC("maps") wifi_stats = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = 3,
};

#define bpf_printk(fmt, ...)					\
({								\
		char ____fmt[] = fmt;				\
		bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
})

SEC("prog")
int mt76_xdp_stats(struct xdp_md *ctx)
{
	u8 *data_end = (u8 *)(long)ctx->data_end;
	u8 *data = (u8 *)(long)ctx->data;
	struct mt76x02_rxwi *rxwi;
	struct ieee80211_hdr *hdr;
	u32 *stats, key;
	u16 fc;

	rxwi = (struct mt76x02_rxwi *)(data + MT_DMA_HDR_LEN);
	if ((u8 *)rxwi > data_end)
		goto out;

	hdr = (struct ieee80211_hdr *)(rxwi + 1);
	if ((u8 *)hdr > data_end)
		goto out;

	if ((u8 *)(hdr + 1) > data_end)
		goto out;

	fc = __constant_le16_to_cpu(hdr->frame_control);
	key = (fc & IEEE80211_FCTL_FTYPE) >> 2;

	stats = bpf_map_lookup_elem(&wifi_stats, &key);
	if (!stats)
		goto out;

	(*stats)++;
	bpf_printk("pkts %x:%u\n", key, *stats);

out:
	return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
