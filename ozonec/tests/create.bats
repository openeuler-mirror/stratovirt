#! /usr/bin/env bats

load helpers

setup_file()
{
    setup_bundle
}

teardown_file()
{
    remove_test_dir
}

setup()
{
    CONTAINER_ID=$(uuidgen)
    ROOT_DIR="$DEFAULT_ROOT_DIR"
}

teardown()
{
    if [ "$ROOT_DIR" == "$DEFAULT_ROOT_DIR" ]; then
        ozonec kill "$CONTAINER_ID" 9
        ozonec delete "$CONTAINER_ID"
    else
        ozonec --root "$ROOT_DIR" kill "$CONTAINER_ID" 9
        ozonec --root "$ROOT_DIR" delete "$CONTAINER_ID"
    fi
}

@test "ozonec create" {
    ozonec create "$CONTAINER_ID" 3>&-
    check_container_status "$CONTAINER_ID" created ""
    [ -d "$ROOT_DIR/$CONTAINER_ID" ]
    [ -S "$ROOT_DIR/$CONTAINER_ID/notify.sock" ]
    [ -f "$ROOT_DIR/$CONTAINER_ID/state.json" ]
}

@test "ozonec create with absolute path of rootfs" {
    local rootfs_dir="$(pwd)/rootfs"
    update_config '.root.path = "'$rootfs_dir'"'
    ozonec create "$CONTAINER_ID" 3>&-
    check_container_status "$CONTAINER_ID" created ""
}

@test "ozonec create with pidfile" {
    ozonec create --pid-file ./pidfile "$CONTAINER_ID" 3>&-
    local pid=$(cat ./pidfile)
    check_container_status "$CONTAINER_ID" created "" "$pid"
}

@test "ozonec create with duplicate id" {
    ozonec create "$CONTAINER_ID" 3>&-
    check_container_status "$CONTAINER_ID" created ""
    ! ozonec create "$CONTAINER_ID" 3>&-
}

@test "ozonec create with absolute bundle path" {
    local bundle_dir="$(dirname `pwd`)/bundle"
    ozonec create --bundle "$bundle_dir" "$CONTAINER_ID" 3>&-
    check_container_status "$CONTAINER_ID" created ""
}

@test "ozonec create with relative bundle path" {
    local bundle_dir="../bundle"
    ozonec create --bundle "$bundle_dir" "$CONTAINER_ID" 3>&-
    check_container_status "$CONTAINER_ID" created ""
}

@test "ozonec create with absolute root path" {
    ROOT_DIR="$(dirname `pwd`)/root"
    ozonec --root "$ROOT_DIR" create "$CONTAINER_ID" 3>&-
    check_container_status "$CONTAINER_ID" created "$ROOT_DIR"
    [ -d "$ROOT_DIR/$CONTAINER_ID" ]
    [ -S "$ROOT_DIR/$CONTAINER_ID/notify.sock" ]
    [ -f "$ROOT_DIR/$CONTAINER_ID/state.json" ]
}

@test "ozonec create with relative root path" {
    ROOT_DIR="../root"
    ozonec --root "$ROOT_DIR" create "$CONTAINER_ID" 3>&-
    check_container_status "$CONTAINER_ID" created "$ROOT_DIR"
    [ -d "$ROOT_DIR/$CONTAINER_ID" ]
    [ -S "$ROOT_DIR/$CONTAINER_ID/notify.sock" ]
    [ -f "$ROOT_DIR/$CONTAINER_ID/state.json" ]
}