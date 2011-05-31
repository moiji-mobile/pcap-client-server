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

#include <osmocom/core/talloc.h>

#include <string.h>

void osmo_pcap_server_delete(struct osmo_pcap_conn *conn)
{
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

	llist_add_tail(&conn->entry, &server->conn);
	return conn;
}

int osmo_pcap_server_listen(struct osmo_pcap_server *server)
{
	return -1;
}
