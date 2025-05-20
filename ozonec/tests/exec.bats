#! /usr/bin/env bats

load helpers

setup_file()
{
    setup_bundle

    export ROOT_DIR="$TEST_DIR/root"
    export CONTAINER_ID=$(uuidgen)

    ozonec --root "$ROOT_DIR"  create "$CONTAINER_ID" 3>&-
    check_container_status "$CONTAINER_ID" created "$ROOT_DIR"
    ozonec --root "$ROOT_DIR" start "$CONTAINER_ID"
    check_container_status "$CONTAINER_ID" running "$ROOT_DIR"
}

teardown_file()
{
    ozonec --root "$ROOT_DIR" kill "$CONTAINER_ID" 9
    ozonec --root "$ROOT_DIR" delete "$CONTAINER_ID"
}

@test "ozonec exec" {
    ozonec --root "$ROOT_DIR" exec "$CONTAINER_ID" -- ls -alh
}

@test "ozonec exec with pidfile" {
    ozonec --root "$ROOT_DIR" exec --pid-file pidfile "$CONTAINER_ID" -- ls -alh
    local pid=$(cat pidfile)
    [[ "$pid" -gt 0 ]]
}