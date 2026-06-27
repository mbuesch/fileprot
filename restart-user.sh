#!/bin/sh

basedir="$(dirname "$(realpath "$0")")"

[ -f "$basedir/Cargo.toml" ] || die "basedir sanity check failed"
. "$basedir/scripts/lib.sh"

entry_checks()
{
    [ "$(id -u)" != "0" ] || die "Must NOT be root to restart fileprot user service."
}

entry_checks
do_systemctl --user daemon-reload
do_systemctl --user enable --now fileprot.service
do_systemctl --user restart fileprot.service
