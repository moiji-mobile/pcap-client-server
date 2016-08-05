/*
 * osmo-pcap-server code
 *
 * (C) 2011-2016 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <zmq.h>

#include <unistd.h>
#include <errno.h>
#include <string.h>


#define SERVER_STR "Server settings\n"
#define CLIENT_STR "Client\n"

static struct cmd_node server_node = {
	SERVER_NODE,
	"%s(server)#",
	1,
};

static int config_write_server(struct vty *vty)
{
	struct osmo_pcap_conn *conn;

	vty_out(vty, "server%s", VTY_NEWLINE);

	if (pcap_server->base_path)
		vty_out(vty, " base-path %s%s", pcap_server->base_path, VTY_NEWLINE);
	if (pcap_server->addr)
		vty_out(vty, " server ip %s%s", pcap_server->addr, VTY_NEWLINE);
	if (pcap_server->port > 0)
		vty_out(vty, " server port %d%s", pcap_server->port, VTY_NEWLINE);
	vty_out(vty, " max-file-size %llu%s",
		(unsigned long long) pcap_server->max_size, VTY_NEWLINE);
	if (pcap_server->zmq_port > 0)
		vty_out(vty, " zeromq-publisher %s %d%s",
			pcap_server->zmq_ip, pcap_server->zmq_port, VTY_NEWLINE);

	llist_for_each_entry(conn, &pcap_server->conn, entry) {
		vty_out(vty, " client %s %s%s%s",
			conn->name, conn->remote_host,
			conn->no_store ? " no-store" : "",
			VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_server,
      cfg_server_cmd,
      "server",
      "Enter the server configuration\n")
{
	vty->node = SERVER_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_server_base,
      cfg_server_base_cmd,
      "base-path PATH",
      "Base path for log files\n" "Path\n")
{
	talloc_free(pcap_server->base_path);
	pcap_server->base_path = talloc_strdup(pcap_server, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_server_ip,
      cfg_server_ip_cmd,
      "server ip A.B.C.D",
      SERVER_STR "Listen\n" "IP Address\n")
{
	talloc_free(pcap_server->addr);
	pcap_server->addr = talloc_strdup(pcap_server, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_server_port,
      cfg_server_port_cmd,
      "server port <1-65535>",
      SERVER_STR "Port\n" "Port Number\n")
{
	pcap_server->port = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_server_max_size,
      cfg_server_max_size_cmd,
      "max-file-size NR",
      "Maximum file size for a trace\n" "Filesize in bytes\n")
{
	pcap_server->max_size = strtoull(argv[0], NULL, 10);
	return CMD_SUCCESS;
}

DEFUN(cfg_server_client,
      cfg_server_client_cmd,
      "client NAME A.B.C.D [no-store]",
      CLIENT_STR "Remote name used in filenames\n" "IP of the remote\n" "Do not store traffic\n")
{
	struct osmo_pcap_conn *conn;
	conn = osmo_pcap_server_find(pcap_server, argv[0]);
	if (!conn) {
		vty_out(vty, "Failed to create a pcap server.\n");
		return CMD_WARNING;
	}

	talloc_free(conn->remote_host);
	conn->remote_host = talloc_strdup(pcap_server, argv[1]);
	inet_aton(argv[1], &conn->remote_addr);

	/* Checking no-store and maybe closing a pcap file */
	if (argc >= 3) {
		osmo_pcap_server_close_trace(conn);
		conn->no_store = 1;
	} else
		conn->no_store = 0;

	return CMD_SUCCESS;
}

DEFUN(cfg_server_no_client,
      cfg_server_no_client_cmd,
      "no client NAME",
      NO_STR CLIENT_STR "The name\n")
{
	struct osmo_pcap_conn *conn;
	conn = osmo_pcap_server_find(pcap_server, argv[0]);
	if (!conn) {
		vty_out(vty, "Failed to create a pcap server.\n");
		return CMD_WARNING;
	}

	osmo_pcap_server_delete(conn);
	return CMD_SUCCESS;
}

void destroy_zmq(struct vty *vty)
{
	if (pcap_server->zmq_publ) {
		int rc = zmq_close(pcap_server->zmq_publ);
		pcap_server->zmq_publ = NULL;
		if (rc != 0)
			vty_out(vty, "%%Failed to close publisher rc=%d errno=%d/%s%s",
				rc, errno, strerror(errno), VTY_NEWLINE);
	}
	if (pcap_server->zmq_ctx) {
		int rc = zmq_ctx_destroy(pcap_server->zmq_ctx);
		pcap_server->zmq_ctx = NULL;
		if (rc != 0)
			vty_out(vty, "%%Failed to destroy ctx rc=%d errno=%d/%s%s",
				rc, errno, strerror(errno), VTY_NEWLINE);
	}
}

DEFUN(cfg_server_zmq_ip_port,
      cfg_server_zmq_ip_port_cmd,
      "zeromq-publisher (A.B.C.D|*) <1-65535>",
      "Enable publishing data to ZeroMQ\n"
      "Bind to IPv4 address\n" "Bind to wildcard\n"
      "Bind to port\n")
{
	int linger, rc;
	char *bind_str;

	destroy_zmq(vty);
	talloc_free(pcap_server->zmq_ip);
	pcap_server->zmq_ip = talloc_strdup(pcap_server, argv[0]);
	if (!pcap_server->zmq_ip) {
		vty_out(vty, "%%Failed to allocate ip string%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	pcap_server->zmq_port = atoi(argv[1]);

	pcap_server->zmq_ctx = zmq_ctx_new();
	if (!pcap_server->zmq_ctx) {
		vty_out(vty, "%%Failed to create zmq ctx%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	pcap_server->zmq_publ = zmq_socket(pcap_server->zmq_ctx, ZMQ_PUB);
	if (!pcap_server->zmq_publ) {
		vty_out(vty, "%%Failed to create zmq publisher%s", VTY_NEWLINE);
		destroy_zmq(vty);
		return CMD_WARNING;
	}

	linger = 0;
	rc = zmq_setsockopt(pcap_server->zmq_publ, ZMQ_LINGER, &linger, sizeof(linger));
	if (rc != 0) {
		vty_out(vty, "%%Failed to set linger option rc=%d errno=%d/%s%s",
			rc, errno, strerror(errno), VTY_NEWLINE);
		destroy_zmq(vty);
		return CMD_WARNING;
	}

	bind_str = talloc_asprintf(pcap_server->zmq_ip, "tcp://%s:%d",
				pcap_server->zmq_ip, pcap_server->zmq_port);
	rc = zmq_bind(pcap_server->zmq_publ, bind_str);
	if (rc != 0) {
		vty_out(vty, "%%Failed to bind zmq publ rc=%d errno=%d/%s%s",
			rc, errno, strerror(errno), VTY_NEWLINE);
		destroy_zmq(vty);
		talloc_free(bind_str);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

DEFUN(cfg_no_server_zmq_ip_port,
      cfg_no_server_zmq_ip_port_cmd,
      "no zeromq-publisher",
      NO_STR "Disable zeromq-publishing\n")
{
	destroy_zmq(vty);
	talloc_free(pcap_server->zmq_ip);
	pcap_server->zmq_ip = NULL;
	pcap_server->zmq_port = 0;
	return CMD_SUCCESS;
}

void vty_server_init(struct osmo_pcap_server *server)
{
	install_element(CONFIG_NODE, &cfg_server_cmd);
	install_node(&server_node, config_write_server);
	install_default(SERVER_NODE);

	install_element(SERVER_NODE, &cfg_server_base_cmd);
	install_element(SERVER_NODE, &cfg_server_ip_cmd);
	install_element(SERVER_NODE, &cfg_server_port_cmd);
	install_element(SERVER_NODE, &cfg_server_max_size_cmd);
	install_element(SERVER_NODE, &cfg_server_zmq_ip_port_cmd);
	install_element(SERVER_NODE, &cfg_no_server_zmq_ip_port_cmd);

	install_element(SERVER_NODE, &cfg_server_client_cmd);
	install_element(SERVER_NODE, &cfg_server_no_client_cmd);
}
