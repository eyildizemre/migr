# COPR's make_srpm method runs "make -f .copr/Makefile srpm outdir=... spec=..."
# as root in a fresh chroot, in a clone checked out at the requested tag. The
# SRPM is built from that commit, so a tag builds before its GitHub release
# (Source0) is published; the tarball has the same contents as the release's.
srpm:
	dnf -y install git-core rpm-build
	version=$$(sed -n 's/^Version: *//p' $(spec)) && \
	git -c safe.directory='*' archive --prefix=migr-$$version/ \
	    -o $(outdir)/migr-$$version.tar.gz HEAD && \
	rpmbuild -bs --define "_sourcedir $(outdir)" \
	    --define "_srcrpmdir $(outdir)" $(spec)
