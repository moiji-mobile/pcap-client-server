/*
 * osmo-pcap-server code
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

#include <osmo-pcap/osmo_pcap_server.h>
#include <osmo-pcap/common.h>
#include <osmo-pcap/wireformat.h>

#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

static void close_connection(struct osmo_pcap_conn *conn)
{
	if (conn->rem_fd.fd >= 0) {
		close(conn->rem_fd.fd);
		conn->rem_fd.fd = -1;
		osmo_fd_unregister(&conn->rem_fd);
	}

	if (conn->local_fd >= 0) {
		close(conn->local_fd);
		conn->local_fd = -1;
	}
}

static void restart_pcap(struct osmo_pcap_conn *conn)
{
	time_t now = time(NULL);
	struct tm *tm = localtime(&now);
	char *filename;
	int rc;

	if (conn->local_fd >= 0) {
		close(conn->local_fd);
		conn->local_fd = -1;
	}

	filename = talloc_asprintf(conn, "%s/trace-%s-%d%.2d%.2d_%.2d%.2d%.2d.pcap",
				   conn->server->base_path, conn->name,
				   tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
				   tm->tm_hour, tm->tm_min, tm->tm_sec);

	if (!filename) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to assemble filename for %s.\n", conn->name);
		return;
	}

	conn->local_fd = creat(filename, 0440);
	if (conn->local_fd < 0) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to file: '%s'\n", filename);
		talloc_free(filename);
		return;
	}

	rc = write(conn->local_fd, &conn->file_hdr, sizeof(conn->file_hdr));
	if (rc != sizeof(conn->file_hdr)) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to write the header: %d\n", errno);
		close(conn->local_fd);
		conn->local_fd = -1;
		talloc_free(filename);
		return;
	}

	conn->last_write = *tm;
	talloc_free(filename);
}

static void link_data(struct osmo_pcap_conn *conn, struct osmo_pcap_data *data)
{
	struct pcap_file_header *hdr;

	if (data->len != sizeof(*hdr)) {
		LOGP(DSERVER, LOGL_ERROR, "The pcap_file_header does not fit.\n");
		close_connection(conn);
		return;
	}

	hdr = (struct pcap_file_header *) &data->data[0];
	if (conn->local_fd < 0) {
		conn->file_hdr = *hdr;
		restart_pcap(conn);
	} else if (memcmp(&conn->file_hdr, hdr, sizeof(*hdr)) != 0) {
		conn->file_hdr = *hdr;
		restart_pcap(conn);
	}
}

/*
 * Check if we are past the limit or on a day change
 */
static void write_data(struct osmo_pcap_conn *conn, struct osmo_pcap_data *data)
{
	time_t now = time(NULL);
	struct tm *tm = localtime(&now);
	int rc;

	if (conn->local_fd < -1) {
		LOGP(DSERVER, LOGL_ERROR, "No file is open. close connection.\n");
		close_connection(conn);
		return; 
	}

	off_t cur = lseek(conn->local_fd, 0, SEEK_CUR);
	if (cur > conn->server->max_size) {
		LOGP(DSERVER, LOGL_NOTICE, "Rolling over file for %s\n", conn->name);
		restart_pcap(conn);
	} else if (conn->last_write.tm_mday != tm->tm_mday ||
		   conn->last_write.tm_mon != tm->tm_mon ||
		   conn->last_write.tm_year != tm->tm_year) {
		LOGP(DSERVER, LOGL_NOTICE, "Rolling over file for %s\n", conn->name);
		restart_pcap(conn);
	}

	conn->last_write = *tm;
	rc = write(conn->local_fd, &data->data[0], data->len);
	if (rc != data->len) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to write for %s\n", conn->name);
		close_connection(conn);
	}
}


void osmo_pcap_server_delete(struct osmo_pcap_conn *conn)
{
	close_connection(conn);
	llist_del(&conn->entry);
	talloc_free(conn);
}

struct osmo_pcap_conn *osmo_pcap_server_find(struct osmo_pcap_server *server,
					     const char *name)
{
	struct osmo_pcap_conn *conn;
	llist_for_each_entry(conn, &server->conn, entry) {
		if (strcmp(conn->name, name) == 0)
			return conn;
	}

	conn = talloc_zero(server, struct osmo_pcap_conn);
	if (!conn) {
		LOGP(DSERVER, LOGL_ERROR,
		     "Failed to find the connection.\n");
		return NULL;
	}

	conn->name = talloc_strdup(conn, name);
	conn->rem_fd.fd = -1;
	conn->local_fd = -1;
	conn->server = server;
	conn->data = (struct osmo_pcap_data *) &conn->buf[0];
	llist_add_tail(&conn->entry, &server->conn);
	return conn;
}

static int read_cb_initial(struct osmo_fd *fd, struct osmo_pcap_conn *conn)
{
	int rc;
	rc = read(fd->fd, &conn->buf[sizeof(*conn->data) - conn->pend], conn->pend);
	if (rc <= 0) {
		LOGP(DSERVER, LOGL_ERROR,
		     "Too short packet. Got %d, wanted %d\n", rc, conn->data->len);
		close_connection(conn);
		return -1;
	}

	conn->pend -= rc;
	if (conn->pend < 0) {
		LOGP(DSERVER, LOGL_ERROR,
		     "Someone got the pending read wrong: %d\n", conn->pend);
		close_connection(conn);
		return -1;
	} else if (conn->pend == 0) {
		conn->data->len = ntohs(conn->data->len);

		if (conn->data->len > 2000) {
			LOGP(DSERVER, LOGL_ERROR,
			     "Unplausible result %u\n", conn->data->len);
			close_connection(conn);
			return -1;
		}

		conn->state = STATE_DATA;
		conn->pend = conn->data->len;
	}

	return 0;
}

static int read_cb_data(struct osmo_fd *fd, struct osmo_pcap_conn *conn)
{
	int rc;
	rc = read(fd->fd, &conn->data->data[conn->data->len - conn->pend], conn->pend);
	if (rc <= 0) {
		LOGP(DSERVER, LOGL_ERROR,
		     "Too short packet. Got %d, wanted %d\n", rc, conn->data->len);
		close_connection(conn);
		return -1;
	}

	conn->pend -= rc;
	if (conn->pend < 0) {
		LOGP(DSERVER, LOGL_ERROR,
		     "Someone got the pending read wrong: %d\n", conn->pend);
		close_connection(conn);
		return -1;
	} else if (conn->pend == 0) {
		conn->state = STATE_INITIAL;
		conn->pend = sizeof(*conn->data);
		switch (conn->data->type) {
		case PKT_LINK_HDR:
			link_data(conn, conn->data);
			break;
		case PKT_LINK_DATA:
			write_data(conn, conn->data);
			break;
		}
	}

	return 0;
}

static int read_cb(struct osmo_fd *fd, unsigned int what)
{
	struct osmo_pcap_conn *conn;

	conn = fd->data;

	if (conn->state == STATE_INITIAL) {
		if (conn->reopen) {
			LOGP(DSERVER, LOGL_INFO, "Reopening log for %s now.\n", conn->name);
			restart_pcap(conn);
			conn->reopen = 0;
		}
		return read_cb_initial(fd, conn);
	} else if (conn->state == STATE_DATA) {
		return read_cb_data(fd, conn);
	}

	return 0;
}

static void new_connection(struct osmo_pcap_server *server,
			   struct osmo_pcap_conn *client, int new_fd)
{
	close_connection(client);

	memset(&client->file_hdr, 0, sizeof(client->file_hdr));
	client->rem_fd.fd = new_fd;
	if (osmo_fd_register(&client->rem_fd) != 0) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to register fd.\n");
		client->rem_fd.fd = -1;
		close(new_fd);
		return;
	}

	client->rem_fd.data = client;
	client->rem_fd.when = BSC_FD_READ;
	client->rem_fd.cb = read_cb;
	client->state = STATE_INITIAL;
	client->pend = sizeof(*client->data);
}

static int accept_cb(struct osmo_fd *fd, unsigned int when)
{
	struct osmo_pcap_conn *conn;
	struct osmo_pcap_server *server;
	struct sockaddr_in addr;
	socklen_t size = sizeof(addr);
	int new_fd;

	new_fd = accept(fd->fd, (struct sockaddr *) &addr, &size);
	if (new_fd < 0) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to accept socket: %d\n", errno);
		return -1;
	}

	server = fd->data;
	llist_for_each_entry(conn, &server->conn, entry) {
		if (conn->remote_addr.s_addr == addr.sin_addr.s_addr) {
			LOGP(DSERVER, LOGL_NOTICE,
			     "New connection from %s\n", conn->name);
			new_connection(server, conn, new_fd);
			return 0;
		}
	}

	LOGP(DSERVER, LOGL_ERROR,
	     "Failed to find client for %s\n", inet_ntoa(addr.sin_addr));
	close(new_fd);
	return -1;
}

int osmo_pcap_server_listen(struct osmo_pcap_server *server)
{
	int fd;

	fd = osmo_sock_init(AF_INET, SOCK_STREAM, IPPROTO_TCP,
			    server->addr, server->port, OSMO_SOCK_F_BIND);
	if (fd < 0) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to create the server socket.\n");
		return -1;
	}

	server->listen_fd.fd = fd;
	server->listen_fd.when = BSC_FD_READ;
	server->listen_fd.cb = accept_cb;
	server->listen_fd.data = server;

	if (osmo_fd_register(&server->listen_fd) != 0) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to register the socket.\n");
		close(fd);
		return -1;
	}

	return 0;
}

void osmo_pcap_server_reopen(struct osmo_pcap_server *server)
{
	struct osmo_pcap_conn *conn;
	LOGP(DSERVER, LOGL_INFO, "Reopening all logfiles.\n");
	llist_for_each_entry(conn, &server->conn, entry) {
		/* Write the complete packet out first */
		if (conn->state == STATE_INITIAL) {
			restart_pcap(conn);
		} else {
			LOGP(DSERVER, LOGL_INFO, "Delaying %s until current packet is complete.\n", conn->name);
			conn->reopen = 1;
		}
	}
}
