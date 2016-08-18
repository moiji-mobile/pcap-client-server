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

#include <osmo-pcap/common.h>
#include <osmo-pcap/osmo_pcap_client.h>

#include <osmocom/core/application.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/select.h>
#include <osmocom/core/stats.h>
#include <osmocom/core/talloc.h>

#include <osmocom/vty/logging.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/stats.h>

#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define _GNU_SOURCE
#include <getopt.h>

#include "osmopcapconfig.h"

static const char *config_file = "osmo-pcap-client.cfg";
static int daemonize = 0;

void *tall_bsc_ctx;
struct osmo_pcap_client *pcap_client;
extern void *tall_msgb_ctx;
extern void *tall_ctr_ctx;


static const struct rate_ctr_desc pcap_client_ctr_desc[] = {
	[CLIENT_CTR_CONNECT]		= { "server.connect",		"Connects to the server" },
	[CLIENT_CTR_BYTES]		= { "captured.bytes",		"Captured bytes        " },
	[CLIENT_CTR_PKTS]		= { "captured.pkts",		"Captured packets      " },
	[CLIENT_CTR_2BIG]		= { "bpf.too_big",		"Captured data too big " },
	[CLIENT_CTR_NOMEM]		= { "client.no_mem",		"No memory available   " },
	[CLIENT_CTR_QERR]		= { "client.queue_err",		"Can not queue data    " },
};

static const struct rate_ctr_group_desc pcap_client_ctr_group_desc = {
	.group_name_prefix		= "pcap.client",
	.group_description		= "PCAP Client statistics",
	.num_ctr			= ARRAY_SIZE(pcap_client_ctr_desc),
	.ctr_desc			= pcap_client_ctr_desc,
	.class_id			= OSMO_STATS_CLASS_GLOBAL,
};

static struct vty_app_info vty_info = {
	.name		= "OsmoPCAPClient",
	.version	= PACKAGE_VERSION,
	.go_parent_cb	= osmopcap_go_parent,
	.is_config_node	= osmopcap_is_config_node,
};

static void print_usage()
{
	printf("Usage: osmo_pcap_client\n");
}

static void print_help()
{
	printf("  Some useful help...\n");
	printf("  -h --help this text\n");
	printf("  -D --daemonize Fork the process into a background daemon\n");
	printf("  -d option --debug=DRLL:DCC:DMM:DRR:DRSL:DNM enable debugging\n");
	printf("  -s --disable-color\n");
	printf("  -T --timestamp. Print a timestamp in the debug output.\n");
	printf("  -e --log-level number. Set a global loglevel.\n");
	printf("  -c --config-file filename The config file to use.\n");
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"daemonize", 0, 0, 'D'},
			{"debug", 1, 0, 'd'},
			{"disable-color", 0, 0, 's'},
			{"timestamp", 0, 0, 'T'},
			{"log-level", 1, 0, 'e'},
			{"config-file", 1, 0, 'c'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hd:DsTc:e:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
			print_help();
			exit(0);
		case 'D':
			daemonize = 1;
			break;
		case 'd':
			log_parse_category_mask(osmo_stderr_target, optarg);
			break;
		case 's':
			log_set_use_color(osmo_stderr_target, 0);
			break;
		case 'T':
			log_set_print_timestamp(osmo_stderr_target, 1);
			break;
		case 'e':
			log_set_log_level(osmo_stderr_target, atoi(optarg));
			break;
		case 'c':
			config_file = strdup(optarg);
			break;
		default:
			/* ignore */
			break;
		}
	}
}

static void signal_handler(int signal)
{
	fprintf(stdout, "signal %u received\n", signal);

	switch (signal) {
	case SIGINT:
		exit(0);
		break;
	case SIGABRT:
		/* in case of abort, we want to obtain a talloc report
		 * and then return to the caller, who will abort the process */
	case SIGUSR1:
		talloc_report(tall_vty_ctx, stderr);
		talloc_report_full(tall_bsc_ctx, stderr);
		break;
	default:
		break;
	}
}

static void talloc_init_ctx()
{
	tall_bsc_ctx = talloc_named_const(NULL, 0, "nat");
	tall_msgb_ctx = talloc_named_const(tall_bsc_ctx, 0, "msgb");
	tall_ctr_ctx = talloc_named_const(tall_bsc_ctx, 0, "counter");
}

int main(int argc, char **argv)
{
	int rc;

	talloc_init_ctx();
	osmo_init_logging(&log_info);

	vty_info.copyright = osmopcap_copyright;
	vty_init(&vty_info);
	logging_vty_add_cmds(&log_info);
	osmo_stats_vty_add_cmds(&log_info);

	/* parse options */
	handle_options(argc, argv);

	rate_ctr_init(tall_bsc_ctx);
	osmo_stats_init(tall_bsc_ctx);

	/* seed the PRNG */
	srand(time(NULL));


	signal(SIGINT, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	osmo_init_ignore_signals();

	rc = telnet_init(tall_bsc_ctx, NULL, 4240);
	if (rc < 0) {
		LOGP(DCLIENT, LOGL_ERROR, "Failed to bind telnet interface\n");
		exit(1);
	}

	pcap_client = talloc_zero(tall_bsc_ctx, struct osmo_pcap_client);
	if (!pcap_client) {
		LOGP(DCLIENT, LOGL_ERROR, "Failed to allocate osmo_pcap_client.\n");
		exit(1);
	}
	pcap_client->fd.fd = -1;
	vty_client_init(pcap_client);

	/* initialize the queue */
	osmo_wqueue_init(&pcap_client->wqueue, 10);
	pcap_client->wqueue.bfd.fd = -1;

	/* initialize the stats interface */
	pcap_client->ctrg = rate_ctr_group_alloc(pcap_client, &pcap_client_ctr_group_desc, 0);
	if (!pcap_client->ctrg) {
		LOGP(DCLIENT, LOGL_ERROR, "Failed to allocate rate ctr\n");
		exit(1);
	}

	if (vty_read_config_file(config_file, NULL) < 0) {
		LOGP(DCLIENT, LOGL_ERROR,
		     "Failed to parse the config file: %s\n", config_file);
		exit(1);
	}

	/* attempt to connect to the remote */
	osmo_client_connect(pcap_client);

	if (daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			exit(1);
		}
	}

	while (1) {
		osmo_select_main(0);
	}

	return(0);
}
