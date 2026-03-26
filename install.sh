#!/bin/sh

basedir="$(realpath "$0" | xargs dirname)"

. "$basedir/scripts/lib.sh"

entry_checks()
{
    [ -f "$target/fileprotd" ] || die "fileprot is not built! Run: cargo build --release"
    [ -f "$target/fileprot" ]  || die "fileprot is not built! Run: cargo build --release"

    [ "$(id -u)" = "0" ] || die "Must be root to install fileprot."
}

install_binaries()
{
    do_install \
        -o root -g root -m 0755 \
        -d /opt/fileprot/bin

    do_install \
        -o root -g root -m 0755 \
        "$target/fileprotd" \
        /opt/fileprot/bin/fileprotd

    do_install \
        -o root -g root -m 0755 \
        "$target/fileprot" \
        /opt/fileprot/bin/fileprot
}

install_conf()
{
    do_install \
        -o root -g root -m 0755 \
        -d /opt/fileprot/etc/fileprot

    if [ -e /opt/fileprot/etc/fileprot/fileprot.conf ]; then
        do_chown \
            root:root \
            /opt/fileprot/etc/fileprot/fileprot.conf
        do_chmod \
            0640 \
            /opt/fileprot/etc/fileprot/fileprot.conf
    else
        do_install \
            -o root -g root -m 0640 \
            "$basedir/fileprot.conf.example" \
            /opt/fileprot/etc/fileprot/fileprot.conf
    fi
}

install_backing()
{
    do_install \
        -o root -g root -m 0700 \
        -d /opt/fileprot/var/lib/fileprot-backing
}

install_dbus()
{
    do_install \
        -o root -g root -m 0644 \
        "$basedir/dbus/ch.bues.fileprot.Daemon.conf" \
        /etc/dbus-1/system.d/ch.bues.fileprot.Daemon.conf

    do_systemctl reload dbus
}

install_service()
{
    do_install \
        -o root -g root -m 0644 \
        "$basedir/systemd/fileprotd.service" \
        /etc/systemd/system/fileprotd.service
}

release="release"
while [ $# -ge 1 ]; do
    case "$1" in
        --debug|-d)
            release="debug"
            ;;
        --release|-r)
            release="release"
            ;;
        *)
            die "Invalid option: $1"
            ;;
    esac
    shift
done
target="$basedir/target/$release"

entry_checks
stop_service
disable_service
install_binaries
install_conf
install_backing
install_dbus
install_service
do_systemctl daemon-reload
start_service
