AUTOMAKE_OPTIONS = foreign dist-bzip2 1.6

SUBDIRS = include src contrib

BUILT_SOURCES = $(top_srcdir)/.version
EXTRA_DIST = git-version-gen .version
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version
