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
#include <osmo-pcap/wireformat.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>

#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <limits.h>
#include <string.h>
#include <unistd.h>

static void _osmo_client_connect(void *_data)
{
	osmo_client_connect((struct osmo_pcap_client *) _data);
}

static void lost_connection(struct osmo_pcap_client *client)
{
	if (client->wqueue.bfd.fd >= 0) {
		osmo_fd_unregister(&client->wqueue.bfd);
		close(client->wqueue.bfd.fd);
		client->wqueue.bfd.fd = -1;
	}


	client->timer.cb = _osmo_client_connect;
	client->timer.data = client;
	osmo_timer_schedule(&client->timer, 2, 0);
}

static void write_data(struct osmo_pcap_client *client, struct msgb *msg)
{
	if (osmo_wqueue_enqueue(&client->wqueue, msg) != 0) {
		LOGP(DCLIENT, LOGL_ERROR, "Failed to enqueue.\n");
		msgb_free(msg);
		return;
	}
}

static int read_cb(struct osmo_fd *fd)
{
	char buf[4096];
	int rc;

	rc = read(fd->fd, buf, sizeof(buf));
	if (rc <= 0) {
		struct osmo_pcap_client *client = fd->data;
		LOGP(DCLIENT, LOGL_ERROR, "Lost connection on read.\n");
		lost_connection(client);
		return -1;
	}

	return 0;
}

static int write_cb(struct osmo_fd *fd, struct msgb *msg)
{
	int rc;

	rc = write(fd->fd, msg->data, msg->len);
	if (rc < 0) {
		struct osmo_pcap_client *client = fd->data;
		LOGP(DCLIENT, LOGL_ERROR, "Lost connection on write.\n");
		lost_connection(client);
		return -1;
	}

	return 0;
}

void osmo_client_send_data(struct osmo_pcap_client *client,
			   struct pcap_pkthdr *in_hdr, const uint8_t *data)
{
	struct osmo_pcap_data *om_hdr;
	struct pcap_pkthdr *hdr;
	struct msgb *msg;

	msg = msgb_alloc(4096, "data-data");
	if (!msg) {
		LOGP(DCLIENT, LOGL_ERROR, "Failed to allocate.\n");
		return;
	}

	om_hdr = (struct osmo_pcap_data *) msgb_put(msg, sizeof(*om_hdr));
	om_hdr->type = PKT_LINK_DATA;

	msg->l2h = msgb_put(msg, sizeof(*hdr));
	hdr = (struct pcap_pkthdr *) msg->l2h;
	*hdr = *in_hdr;

	msg->l3h = msgb_put(msg, in_hdr->caplen);
	memcpy(msg->l3h, data, in_hdr->caplen);

	om_hdr->len = htons(msgb_l2len(msg));

	write_data(client, msg);
}

void osmo_client_send_link(struct osmo_pcap_client *client)
{
	struct pcap_file_header *hdr;
	struct osmo_pcap_data *om_hdr;

	struct msgb *msg = msgb_alloc(4096, "link-data");
	if (!msg) {
		LOGP(DCLIENT, LOGL_ERROR, "Failed to allocate data.\n");
		return;
	}


	om_hdr = (struct osmo_pcap_data *) msgb_put(msg, sizeof(*om_hdr));
	om_hdr->type = PKT_LINK_HDR;
	om_hdr->len = htons(sizeof(*hdr));

	hdr = (struct pcap_file_header *) msgb_put(msg, sizeof(*hdr));
	hdr->magic = 0xa1b2c3d4;
	hdr->version_major = 2;
	hdr->version_minor = 4;
	hdr->thiszone = 0;
	hdr->sigfigs = 0;
	hdr->snaplen = UINT_MAX;
	hdr->linktype = pcap_datalink(client->handle);

	write_data(client, msg);
}

void osmo_client_connect(struct osmo_pcap_client *client)
{
	int fd;

	client->wqueue.read_cb = read_cb;
	client->wqueue.write_cb = write_cb;
	client->wqueue.bfd.when = BSC_FD_READ;
	client->wqueue.bfd.data = client;
	osmo_wqueue_clear(&client->wqueue);

	fd = osmo_sock_init(AF_INET, SOCK_STREAM, IPPROTO_TCP,
			    client->srv_ip, client->srv_port, OSMO_SOCK_F_CONNECT);
	if (fd < 0) {
		LOGP(DCLIENT, LOGL_ERROR,
		     "Failed to connect to %s:%d\n",
		     client->srv_ip, client->srv_port);
		lost_connection(client);
		return;
	}

	client->wqueue.bfd.fd = fd;
	if (osmo_fd_register(&client->wqueue.bfd) != 0) {
		LOGP(DCLIENT, LOGL_ERROR,
		     "Failed to register to BFD.\n");
		lost_connection(client);
		return;
	}

	osmo_client_send_link(client);
}
