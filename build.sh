#!/bin/sh

basedir="$(realpath "$0" | xargs dirname)"

[ -f "$basedir/Cargo.toml" ] || die "basedir sanity check failed"
. "$basedir/scripts/lib.sh"

release="both"
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

cd "$basedir" || die "cd basedir failed."

packages_args="-p fileprot -p fileprotd"
packages_release_paths="target/release/fileprot target/release/fileprotd"

# Debug build and test
if [ "$release" = "debug" -o "$release" = "both" ]; then
    cargo build $packages_args || die "Cargo build (debug) failed."
    cargo test $packages_args || die "Cargo test failed."
fi

# Release build
if [ "$release" = "release" -o "$release" = "both" ]; then
    if which cargo-auditable >/dev/null 2>&1; then
        cargo auditable build --release $packages_args \
            || die "Cargo build (release) failed."
        #cargo audit --deny warnings bin $packages_release_paths \
        #    || die "Cargo audit failed."
    else
        cargo build --release $packages_args || die "Cargo build (release) failed."
    fi
fi
