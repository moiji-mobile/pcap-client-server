INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS = -Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(PCAP_CFLAGS)
AM_LDFLAGS = $(LIBOSMOCORE_LIBS) $(LIBOSMOVTY_LIBS)

bin_PROGRAMS = osmo_pcap_client

osmo_pcap_client_SOURCES = osmo_client_main.c
osmo_pcap_client_LDADD = $(PCAP_LIBS)
