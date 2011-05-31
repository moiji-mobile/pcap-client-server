/*
 * osmo-pcap wireforat
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

#ifndef WIREFORMAT_H
#define WIREFORMAT_H

#include <inttypes.h>
#include <pcap.h>

/*
 * Should send an entire pcap header
 */
#define PKT_LINK_HDR	0

/*
 * Should send one packet...
 */
#define PKT_LINK_DATA	1

struct osmo_pcap_data {
	uint8_t type;
	uint8_t spare[3];
	uint32_t len;
	uint8_t data[0];
} __attribute__((packed));

#endif
