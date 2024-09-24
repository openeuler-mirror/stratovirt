#! /bin/bash

bats_require_minimum_version 1.5.0

DEFAULT_ROOT_DIR="/var/run/user/$(echo $UID)/ozonec"

# Reformat config.json file with jq command.
function update_config()
{
    jq "$@" config.json | awk 'BEGIN{RS="";getline<"-";print>ARGV[1]}' config.json
}

function setup_bundle()
{
    # Directory for each container.
    TEST_DIR=$(mktemp -d "$BATS_RUN_TMPDIR/ozonec.XXXXXX")
    chmod a+x "$TEST_DIR" "$BATS_RUN_TMPDIR"

    local bundle="$BATS_TEST_DIRNAME/bundle.tar.gz"
    tar --exclude 'rootfs/dev/*' -C "$TEST_DIR" -xf "$bundle"
    cd "$TEST_DIR/bundle"
}

function remove_test_dir()
{
    rm -rf "$TEST_DIR"
}

function check_container_status() {
    local container_id="$1"
    local state="$2"
    local root="$3"

    if [ "$root" == "" ]; then
        run ozonec state "$container_id"
    else
        run ozonec --root "$root" state "$container_id"
    fi
    [[ $status -eq 0 ]]
    [[ "$output" == *"\"status\": \"$state\""* ]]

    if [ $# -gt 3 ]; then
        local pid="$4"
        [[ "$(expr match "$output" '.*"pid": \([0-9]*\).*')" == "$pid" ]]
    fi
}