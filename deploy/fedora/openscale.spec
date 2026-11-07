# Fedora / RHEL / openSUSE recipe for OpenScale (#317, ADR-0091), for
# rpmbuild, mock or a COPR the owner runs. Builds offline from a source
# archive that contains vendor/ (only tracked files, never keys):
#
#   V=$(cat VERSION); go mod vendor
#   git archive --format=tar --prefix=openscale-$V/ -o openscale-$V.tar HEAD
#   tar --transform "s,^,openscale-$V/," -rf openscale-$V.tar vendor && gzip -n openscale-$V.tar
#   cp deploy/linux/openscale.sysusers .
#   rpmbuild -ba deploy/fedora/openscale.spec --define "_sourcedir $PWD" --define "ver $V"
#
# The ready-made package from scripts/release.sh is built by cmd/pkgrpm
# instead; this spec is for people who build with their distribution's
# tools. Units are installed but never enabled.

%global goipath github.com/openscale/openscale
%global debug_package %{nil}

Name:           openscale
Version:        %{?ver}%{!?ver:0.8.0}
Release:        1%{?dist}
Summary:        Personal, single-owner WireGuard mesh VPN
License:        LicenseRef-OpenScale-Unlicensed
Source0:        %{name}-%{version}.tar.gz
Source1:        openscale.sysusers

ExclusiveArch:  x86_64 aarch64 armv7hl
BuildRequires:  golang >= 1.26
BuildRequires:  systemd-rpm-macros
Requires:       iproute
Recommends:     nftables
%{?systemd_requires}
%{?sysusers_requires_compat}

%description
Coordinator and device for a single-owner, cloud-free WireGuard mesh.
The package installs the program and the systemd units but does not
enable or start them; join the network first.

%prep
%autosetup -n %{name}-%{version}
test -d vendor || { echo "vendor/ yok: kaynak arşivi 'go mod vendor' sonrası üretilmeli" >&2; exit 1; }

%build
export CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS='-mod=vendor -buildvcs=false'
b=$(date -u -d "@${SOURCE_DATE_EPOCH:-0}" +%%Y%%m%%d.%%H%%M)
[ ! -d tools/depcheck ] || go run ./tools/depcheck go.mod
go build -trimpath \
  -ldflags "-s -w -buildid= -X %{goipath}/internal/version.Version=%{version} -X %{goipath}/internal/version.Build=$b" \
  -o openscale ./cmd/openscale
rootkey=$(tr -d ' \r\n' < build/release/root.pub 2>/dev/null || true)
go build -trimpath -ldflags "-s -w -buildid= -X main.embeddedRootKey=$rootkey" \
  -o openscale-release-verify ./cmd/releaseverify

%check
export CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS='-mod=vendor -buildvcs=false'
go test ./internal/osnet/... ./cmd/...

%install
install -Dm0755 openscale %{buildroot}%{_bindir}/openscale
install -Dm0755 openscale-release-verify %{buildroot}%{_bindir}/openscale-release-verify
for u in openscale-coordinator.service openscale-device.service; do
  sed 's#/usr/local/bin/openscale #%{_bindir}/openscale #' deploy/linux/$u > $u
  install -Dm0644 $u %{buildroot}%{_unitdir}/$u
done
install -Dm0644 deploy/linux/openscale.sysusers %{buildroot}%{_sysusersdir}/openscale.conf
install -Dm0644 deploy/linux/openscale.tmpfiles %{buildroot}%{_tmpfilesdir}/openscale.conf
install -d %{buildroot}%{_docdir}/%{name}/examples
install -m0644 deploy/linux/nftables.conf deploy/linux/sshd-openscale.conf \
  deploy/linux/50-openscale-upgrades.conf %{buildroot}%{_docdir}/%{name}/examples/

%pre
%sysusers_create_compat %{SOURCE1}

%post
%tmpfiles_create %{_tmpfilesdir}/openscale.conf
%systemd_post openscale-coordinator.service openscale-device.service

%preun
%systemd_preun openscale-coordinator.service openscale-device.service

%postun
%systemd_postun_with_restart openscale-coordinator.service openscale-device.service

%files
%{_bindir}/openscale
%{_bindir}/openscale-release-verify
%{_unitdir}/openscale-coordinator.service
%{_unitdir}/openscale-device.service
%{_sysusersdir}/openscale.conf
%{_tmpfilesdir}/openscale.conf
%doc %{_docdir}/%{name}/examples
