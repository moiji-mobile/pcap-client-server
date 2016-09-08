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

static void write_tls(struct vty *vty, struct osmo_pcap_server *pcap_server)
{
	if (!pcap_server->tls_on)
		return;

	vty_out(vty, " enable tls%s", VTY_NEWLINE);
	vty_out(vty, " tls log-level %d%s",
		pcap_server->tls_log_level, VTY_NEWLINE);

	if (pcap_server->tls_allow_anon)
		vty_out(vty, " tls allow-auth anonymous%s", VTY_NEWLINE);

	if (pcap_server->tls_allow_x509)
		vty_out(vty, " tls allow-auth x509%s", VTY_NEWLINE);

	if (pcap_server->tls_priority)
		vty_out(vty, " tls priority %s%s",
			pcap_server->tls_priority, VTY_NEWLINE);
	if (pcap_server->tls_capath)
		vty_out(vty, " tls capath %s%s", pcap_server->tls_capath, VTY_NEWLINE);

	if (pcap_server->tls_crlfile)
		vty_out(vty, " tls crlfile %s%s", pcap_server->tls_crlfile, VTY_NEWLINE);

	if (pcap_server->tls_server_cert)
		vty_out(vty, " tls server-cert %s%s",
			pcap_server->tls_server_cert, VTY_NEWLINE);

	if (pcap_server->tls_server_key)
		vty_out(vty, " tls server-key %s%s",
			pcap_server->tls_server_key, VTY_NEWLINE);

	if (pcap_server->tls_dh_pkcs3)
		vty_out(vty, " tls dh pkcs3 %s%s",
			pcap_server->tls_dh_pkcs3, VTY_NEWLINE);
	else
		vty_out(vty, " tls dh generate%s", VTY_NEWLINE);
}

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

	write_tls(vty, pcap_server);

	llist_for_each_entry(conn, &pcap_server->conn, entry) {
		vty_out(vty, " client %s %s%s%s%s",
			conn->name, conn->remote_host,
			conn->no_store ? " no-store" : " store",
			conn->tls_use ? " tls" : "",
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

static int manage_client(struct osmo_pcap_server *pcap_server,
			struct vty *vty,
			const char *name, const char *remote_host,
			bool no_store, bool use_tls)
{
	struct osmo_pcap_conn *conn;
	conn = osmo_pcap_server_find(pcap_server, name);
	if (!conn) {
		vty_out(vty, "Failed to create a pcap server.\n");
		return CMD_WARNING;
	}

	talloc_free(conn->remote_host);
	conn->remote_host = talloc_strdup(pcap_server, remote_host);
	inet_aton(remote_host, &conn->remote_addr);

	/* Checking no-store and maybe closing a pcap file */
	if (no_store) {
		osmo_pcap_server_close_trace(conn);
		conn->no_store = 1;
	} else
		conn->no_store = 0;

	if (use_tls) {
		/* force moving to TLS */
		if (!conn->tls_use)
			osmo_pcap_server_close_conn(conn);
		conn->tls_use = true;
	} else {
		conn->tls_use = false;
	}

	return CMD_SUCCESS;
}


DEFUN(cfg_server_client,
      cfg_server_client_cmd,
      "client NAME A.B.C.D [no-store] [tls]",
      CLIENT_STR "Remote name used in filenames\n"
      "IP of the remote\n" "Do not store traffic\n"
      "Use Transport Level Security\n")
{
	return manage_client(pcap_server, vty, argv[0], argv[1], argc >= 3, argc >= 4);
}

DEFUN(cfg_server_client_store_tls,
      cfg_server_client_store_tls_cmd,
      "client NAME A.B.C.D store [tls]",
      CLIENT_STR "Remote name used in filenames\n"
      "IP of the remote\n" "Do not store traffic\n"
      "Use Transport Level Security\n")
{
	return manage_client(pcap_server, vty, argv[0], argv[1], false, argc >= 3);
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

#define TLS_STR "Transport Layer Security"

DEFUN(cfg_enable_tls,
      cfg_enable_tls_cmd,
      "enable tls",
      "Enable\n" "Transport Layer Security\n")
{
	pcap_server->tls_on = true;
	return CMD_SUCCESS;
}

DEFUN(cfg_disable_tls,
      cfg_disable_tls_cmd,
      "disable tls",
      "Disable\n" "Transport Layer Security\n")
{
	pcap_server->tls_on = false;
	return CMD_SUCCESS;
}

DEFUN(cfg_tls_log_level,
      cfg_tls_log_level_cmd,
      "tls log-level <0-255>",
      TLS_STR "Log-level\n" "GNUtls debug level\n")
{
	pcap_server->tls_log_level = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_tls_allow_anon,
      cfg_tls_allow_anon_cmd,
      "tls allow-auth anonymous",
      TLS_STR "allow authentication\n" "for anonymous\n")
{
	pcap_server->tls_allow_anon = true;
	return CMD_SUCCESS;
}

DEFUN(cfg_no_tls_allow_anon,
      cfg_no_tls_allow_anon_cmd,
      "no tls allow-auth anonymous",
      NO_STR TLS_STR "allow authentication\n" "for anonymous\n")
{
	pcap_server->tls_allow_anon = false;
	return CMD_SUCCESS;
}

DEFUN(cfg_tls_allow_x509,
      cfg_tls_allow_x509_cmd,
      "tls allow-auth x509",
      TLS_STR "allow authentication\n" "for certificates\n")
{
	pcap_server->tls_allow_x509 = true;
	return CMD_SUCCESS;
}

DEFUN(cfg_no_tls_allow_x509,
      cfg_no_tls_allow_x509_cmd,
      "no tls allow-auth x509",
      NO_STR TLS_STR "allow authentication\n" "for certificates\n")
{
	pcap_server->tls_allow_x509 = false;
	return CMD_SUCCESS;
}

DEFUN(cfg_tls_priority,
      cfg_tls_priority_cmd,
      "tls priority STR",
      TLS_STR "Priority string for GNUtls\n")
{
	talloc_free(pcap_server->tls_priority);
	pcap_server->tls_priority = talloc_strdup(pcap_server, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_no_tls_priority,
      cfg_no_tls_priority_cmd,
      "no tls priority",
      NO_STR TLS_STR "Priority string for GNUtls\n")
{
	talloc_free(pcap_server->tls_priority);
	pcap_server->tls_priority = NULL;
	return CMD_SUCCESS;
}

DEFUN(cfg_tls_capath,
      cfg_tls_capath_cmd,
      "tls capath .PATH",
      TLS_STR "Trusted root certificates\n" "Filename\n")
{
	talloc_free(pcap_server->tls_capath);
	pcap_server->tls_capath = talloc_strdup(pcap_server, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_no_tls_capath,
      cfg_no_tls_capath_cmd,
      "no tls capath",
      NO_STR TLS_STR "Trusted root certificates\n")
{
	talloc_free(pcap_server->tls_capath);
	pcap_server->tls_capath = NULL;
	return CMD_SUCCESS;
}

DEFUN(cfg_tls_crlfile,
      cfg_tls_crlfile_cmd,
      "tls crlfile .PATH",
      TLS_STR "CRL file\n" "Filename\n")
{
	talloc_free(pcap_server->tls_crlfile);
	pcap_server->tls_crlfile = talloc_strdup(pcap_server, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_no_tls_crlfile,
      cfg_no_tls_crlfile_cmd,
      "no tls crlfile",
      NO_STR TLS_STR "CRL file\n")
{
	talloc_free(pcap_server->tls_crlfile);
	pcap_server->tls_crlfile = NULL;
	return CMD_SUCCESS;
}

DEFUN(cfg_tls_server_cert,
      cfg_tls_server_cert_cmd,
      "tls server-cert .PATH",
      TLS_STR "Server certificate\n" "Filename\n")
{
	talloc_free(pcap_server->tls_server_cert);
	pcap_server->tls_server_cert = talloc_strdup(pcap_server, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_no_tls_server_cert,
      cfg_no_tls_server_cert_cmd,
      "no tls server-cert",
      NO_STR TLS_STR "Server certificate\n")
{
	talloc_free(pcap_server->tls_server_cert);
	pcap_server->tls_server_cert = NULL;
	return CMD_SUCCESS;
}

DEFUN(cfg_tls_server_key,
      cfg_tls_server_key_cmd,
      "tls server-key .PATH",
      TLS_STR "Server private key\n" "Filename\n")
{
	talloc_free(pcap_server->tls_server_key);
	pcap_server->tls_server_key = talloc_strdup(pcap_server, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_no_tls_server_key,
      cfg_no_tls_server_key_cmd,
      "no tls server-key",
      NO_STR TLS_STR "Server private key\n")
{
	talloc_free(pcap_server->tls_server_key);
	pcap_server->tls_server_key = NULL;
	return CMD_SUCCESS;
}

DEFUN(cfg_tls_dh_pkcs3,
      cfg_tls_dh_pkcs3_cmd,
      "tls dh pkcs .FILE",
      TLS_STR "Diffie-Hellman Key Exchange\n" "PKCS3\n")
{
	talloc_free(pcap_server->tls_dh_pkcs3);
	pcap_server->tls_dh_pkcs3 = talloc_strdup(pcap_server, argv[0]);

	osmo_tls_dh_load(pcap_server);
	return CMD_SUCCESS;
}

DEFUN(cfg_tls_dh_generate,
      cfg_tls_dh_generate_cmd,
      "tls dh generate",
      TLS_STR "Diffie-Hellman Key Exchange\n" "Generate prime\n")
{
	talloc_free(pcap_server->tls_dh_pkcs3);
	pcap_server->tls_dh_pkcs3 = NULL;

	osmo_tls_dh_generate(pcap_server);
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

	/* tls for the server */
	install_element(SERVER_NODE, &cfg_enable_tls_cmd);
	install_element(SERVER_NODE, &cfg_disable_tls_cmd);
	install_element(SERVER_NODE, &cfg_tls_log_level_cmd);
	install_element(SERVER_NODE, &cfg_tls_allow_anon_cmd);
	install_element(SERVER_NODE, &cfg_no_tls_allow_anon_cmd);
	install_element(SERVER_NODE, &cfg_tls_allow_x509_cmd);
	install_element(SERVER_NODE, &cfg_no_tls_allow_x509_cmd);
	install_element(SERVER_NODE, &cfg_tls_priority_cmd);
	install_element(SERVER_NODE, &cfg_no_tls_priority_cmd);
	install_element(SERVER_NODE, &cfg_tls_capath_cmd);
	install_element(SERVER_NODE, &cfg_no_tls_capath_cmd);
	install_element(SERVER_NODE, &cfg_tls_crlfile_cmd);
	install_element(SERVER_NODE, &cfg_no_tls_crlfile_cmd);
	install_element(SERVER_NODE, &cfg_tls_server_cert_cmd);
	install_element(SERVER_NODE, &cfg_no_tls_server_cert_cmd);
	install_element(SERVER_NODE, &cfg_tls_server_key_cmd);
	install_element(SERVER_NODE, &cfg_no_tls_server_key_cmd);
	install_element(SERVER_NODE, &cfg_tls_dh_generate_cmd);
	install_element(SERVER_NODE, &cfg_tls_dh_pkcs3_cmd);

	install_element(SERVER_NODE, &cfg_server_client_cmd);
	install_element(SERVER_NODE, &cfg_server_client_store_tls_cmd);
	install_element(SERVER_NODE, &cfg_server_no_client_cmd);
}
