# OPNsense plugin skeleton of the OpenScale device (#885,
# docs/pfsense-opnsense.md). Copy this directory to net/openscale in a
# checkout of the OPNsense plugins tree and run "make package" there; or
# build without the tree on OPNsense itself: sh build-plugin.sh.
# The plugin only writes /etc/rc.conf.d/openscale and starts or stops the
# service; the program and its rc.d script come from the "openscale"
# package (deploy/pfsense/build-pkg.sh).

PLUGIN_NAME=		openscale
PLUGIN_VERSION=		1.0.0.b2
PLUGIN_COMMENT=		OpenScale WireGuard mesh VPN device (settings and service)
PLUGIN_DEPENDS=		openscale
PLUGIN_MAINTAINER=	root@localhost
PLUGIN_WWW=		https://example.com/openscale
PLUGIN_DEVEL=		yes

.include "../../Mk/plugins.mk"
