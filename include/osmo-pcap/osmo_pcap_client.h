/*
 * osmo-pcap-client code
 *
 * (C) 2011 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <pcap.h>

#include <osmocom/core/select.h>


struct osmo_pcap_client {
	char *device;
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];

	struct bpf_program bpf;
	char   *filter_string;
	int filter_itself;

	struct osmo_fd fd;

	char *srv_ip;
	int srv_port;
};

extern struct osmo_pcap_client *pcap_client;

int vty_client_init(struct osmo_pcap_client *);

int osmo_client_capture(struct osmo_pcap_client *client, const char *device);
int osmo_client_filter(struct osmo_pcap_client *client, const char *filter);
