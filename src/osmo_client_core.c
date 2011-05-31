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

#include <osmo-pcap/osmo_pcap_client.h>
#include <osmo-pcap/common.h>

#include <osmocom/core/talloc.h>

#include <limits.h>


static void free_all(struct osmo_pcap_client *client)
{
	if (!client->handle)
		return;

	if (client->bpf) {
		pcap_freecode(client->bpf);
		client->bpf = NULL;
	}

	if (client->fd.fd != -1) {
		osmo_fd_unregister(&client->fd);
		client->fd.fd = -1;
	}

	pcap_close(client->handle);
	client->handle = NULL;
}

int osmo_client_capture(struct osmo_pcap_client *client, const char *device)
{
	talloc_free(client->device);
	free_all(client);

	client->device = talloc_strdup(client, device);
	if (!client) {
		LOGP(DCLIENT, LOGL_ERROR, "Failed to copy string.\n");
		return 1;
	}

	client->handle = pcap_open_live(client->device, 2000, 0,
					1000, client->errbuf);
	if (!client->handle) {
		LOGP(DCLIENT, LOGL_ERROR,
		     "Failed to open the device: %s\n", client->errbuf);
		return 2;
	}

	return 0;
}

int osmo_client_filter(struct osmo_pcap_client *client, const char *filter)
{
	return 0;
}
