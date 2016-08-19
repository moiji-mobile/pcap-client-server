/*
 * osmo-pcap-client code
 *
 * (C) 2011-2016 by Holger Hans Peter Freyther <holger@moiji-mobile.com>
 * (C) 2011 by On-Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <inttypes.h>
#include <pcap.h>

#include <osmocom/core/select.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/write_queue.h>

struct rate_ctr_group;

enum {
	CLIENT_CTR_CONNECT,
	CLIENT_CTR_BYTES,
	CLIENT_CTR_PKTS,
	CLIENT_CTR_2BIG,
	CLIENT_CTR_NOMEM,
	CLIENT_CTR_QERR,
	CLIENT_CTR_PERR,
	CLIENT_CTR_WERR,
};

struct osmo_pcap_client {
	char *device;
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];

	struct bpf_program bpf;
	char   *filter_string;
	int filter_itself;
	int gprs_filtering;
	struct osmo_fd fd;

	char *srv_ip;
	int srv_port;
	struct osmo_wqueue wqueue;
	struct osmo_timer_list timer;

	/* statistics */
	struct rate_ctr_group *ctrg;
};

extern struct osmo_pcap_client *pcap_client;

int vty_client_init(struct osmo_pcap_client *);

int osmo_client_capture(struct osmo_pcap_client *client, const char *device);
int osmo_client_filter(struct osmo_pcap_client *client, const char *filter);

void osmo_client_send_data(struct osmo_pcap_client *client,
			   struct pcap_pkthdr *hdr, const uint8_t *data);
void osmo_client_send_link(struct osmo_pcap_client *client);
void osmo_client_connect(struct osmo_pcap_client *);
