#!/bin/sh
# Prints the version that main.c, the RPM spec, the PKGBUILD, and the Debian
# changelog agree on, or names each place and fails. Given a tag (v1.2.3),
# the version must also be the tag's.
set -eu
main=$(sed -n 's/^#define MIGR_VERSION "\(.*\)"$/\1/p' src/main.c)
spec=$(sed -n 's/^Version: *//p' packaging/fedora/migr.spec)
arch=$(sed -n 's/^pkgver=//p' packaging/arch/PKGBUILD)
deb=$(sed -n '1s/^migr (\([^-]*\)-.*/\1/p' packaging/debian/changelog)
tag=${1:+${1#v}}

if [ -z "$main" ] || [ "$main" != "$spec" ] || [ "$main" != "$arch" ] ||
   [ "$main" != "$deb" ] || { [ -n "$tag" ] && [ "$main" != "$tag" ]; }; then
    echo "Versions differ:" >&2
    echo "  src/main.c                  $main" >&2
    echo "  packaging/fedora/migr.spec  $spec" >&2
    echo "  packaging/arch/PKGBUILD     $arch" >&2
    echo "  packaging/debian/changelog  $deb" >&2
    [ -z "$tag" ] || echo "  tag                         $tag" >&2
    exit 1
fi
echo "$main"
