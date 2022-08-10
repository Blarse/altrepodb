%define _unpackaged_files_terminate_build 1
%def_disable check

%define oname altrepodb
%define servicename uploaderd

Name: altrepodb
Version: 2.3.13
Release: alt1

Summary: ALTRepo Uploader is a set of tools that used to uploading data about ALT Linux distributions to database
License: GPL-3.0
Group: Development/Python3
URL: https://git.altlinux.org/gears/a/altrepodb.git

BuildArch: noarch

Requires: python3-module-rpm
Requires: xz
Requires: git
Requires: fuseiso
Requires: gostsum
Requires: squashfuse
Requires: cdrkit-utils
Requires: libvirt
Requires: qemu-img
Requires: qemu-kvm
Requires: libguestfs
Requires: guestfs-data
Requires: rabbitmq-c

BuildRequires(pre): rpm-build-python3

Source0: %name-%version.tar
Patch1: %name-%version-%release.patch

%description
ALTRepo Uploader (a.k.a ALTRepoDB) is a set of tools that used to
uploading data about ALT Linux distributions to Clickhouse database.
Database contents is used to maintain ALT Linux development and
analytics with ALTRepo API.

%package bot
Summary: ALTRepo Notifier Telegram Bot
Group: Development/Python3

%description bot
%summary

%prep
%setup
%autopatch -p1

%build
%python3_build

%install
%python3_install
mkdir -p %buildroot%_localstatedir/%name
mkdir -p %buildroot%_sysconfdir/%servicename/services.d
install -Dm0644 service/uploaderd.service %buildroot%_unitdir/uploaderd.service
cp -r service/config.json.example %buildroot%_sysconfdir/%servicename/config.json.example
cp -r service/services.d/* %buildroot%_sysconfdir/%servicename/services.d
mkdir -p %buildroot%_logdir/%name

#altrepobot
install -Dm0644 altrepobot/altrepobot.service %buildroot%_unitdir/altrepobot.service
install -Dm0755 altrepobot/altrepobot %buildroot%_bindir/altrepobot
touch %buildroot%_sysconfdir/altrepobot.conf

%pre
%_sbindir/groupadd -r -f _altrepodb 2> /dev/null ||:
%_sbindir/useradd -r -g _altrepodb -s /dev/null -c "ALTRepoDB User" -d %_localstatedir/%name  _altrepodb 2> /dev/null ||:

%pre bot
%_sbindir/groupadd -r -f _altrepodb 2> /dev/null ||:
%_sbindir/useradd -r -g _altrepodb -s /dev/null -c "ALTRepoDB User" -d %_localstatedir/%name  _altrepodb 2> /dev/null ||:

%preun
%preun_service uploaderd

%preun bot
%preun_service altrepobot

%files
%dir %_sysconfdir/%servicename
%dir %attr(0750,_altrepodb,_altrepodb) %_logdir/%name
%dir %attr(0755,_altrepodb,_altrepodb) %_localstatedir/%name
%doc LICENSE README.* AUTHORS.txt CHANGELOG.* config.ini.example sql amqpfire_config.json.example
%_unitdir/*
%exclude %_unitdir/altrepobot.service
%_sysconfdir/%servicename/*
%python3_sitelibdir/%oname/
%python3_sitelibdir/%oname-%version-*.egg-info
%_bindir/uploaderd
%_bindir/acl_loader
%_bindir/beehive_loader
%_bindir/bugzilla_loader
%_bindir/image_loader
%_bindir/iso_loader
%_bindir/package_loader
%_bindir/repo_loader
%_bindir/repocop_loader
%_bindir/spdx_loader
%_bindir/task_cleaner
%_bindir/task_loader
%_bindir/watch_loader
%_bindir/repodb_amqpfire

%files bot
%doc altrepobot/altrepobot.conf.example
%_bindir/altrepobot
%_unitdir/altrepobot.service
%attr(0640, root, _altrepodb) %ghost %_sysconfdir/altrepobot.conf

%changelog
* Tue Aug 09 2022 Egor Ignatov <egori@altlinux.org> 2.3.13-alt1
 - new version 2.3.13
   + add altrepobot

* Tue Aug 09 2022 Danil Shein <dshein@altlinux.org> 2.3.12-alt1
 - new version 2.3.12

* Thu Aug 04 2022 Danil Shein <dshein@altlinux.org> 2.3.11-alt1
 - new version 2.3.11

* Wed Aug 03 2022 Danil Shein <dshein@altlinux.org> 2.3.10-alt1
 - new version 2.3.10

* Mon Jul 11 2022 Danil Shein <dshein@altlinux.org> 2.3.9-alt1
 - new version 2.3.9

* Mon Jul 04 2022 Danil Shein <dshein@altlinux.org> 2.3.8-alt1
 - new version 2.3.8

* Thu Jun 30 2022 Danil Shein <dshein@altlinux.org> 2.3.7-alt1
 - new version 2.3.7

* Wed Jun 29 2022 Danil Shein <dshein@altlinux.org> 2.3.6-alt1
 - new version 2.3.6

* Tue Jun 28 2022 Danil Shein <dshein@altlinux.org> 2.3.5-alt1
 - new version 2.3.5

* Thu Jun 23 2022 Danil Shein <dshein@altlinux.org> 2.3.4-alt1
 - new version 2.3.4
   + added acl_loder service

* Thu Jun 23 2022 Danil Shein <dshein@altlinux.org> 2.3.3-alt1
 - new version 2.3.3
   + named uploaderdd processes

* Wed Jun 22 2022 Danil Shein <dshein@altlinux.org> 2.3.2-alt1
 - new version

* Tue Jun 21 2022 Danil Shein <dshein@altlinux.org> 2.3.1-alt1
 - new version

* Fri Jun 03 2022 Danil Shein <dshein@altlinux.org> 2.3.0-alt1
- test build
