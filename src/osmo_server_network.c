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

#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>

static void close_connection(struct osmo_pcap_conn *conn)
{
	if (conn->rem_fd.fd != -1) {
		close(conn->rem_fd.fd);
		conn->rem_fd.fd = -1;
		osmo_fd_unregister(&conn->rem_fd);
	}

	if (conn->local_fd != -1) {
		close(conn->local_fd);
		conn->local_fd = -1;
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
	conn->server = server;
	llist_add_tail(&conn->entry, &server->conn);
	return conn;
}

static int read_cb(struct osmo_fd *fd, unsigned int what)
{
	struct osmo_pcap_conn *conn;
	char buf[4096];
	int rc;

	conn = fd->data;
	rc = read(fd->fd, buf, sizeof(buf));
	if (rc < 0) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to read from %s\n", conn->name);
		close_connection(conn);
		return -1;
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
			    server->addr, server->port, 1);
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
