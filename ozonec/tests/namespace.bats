#! /usr/bin/env bats

load helpers

setup_file()
{
    setup_bundle
}

setup()
{
    CONTAINER_ID=$(uuidgen)
}

teardown()
{
    ozonec kill "$CONTAINER_ID" 9
    ozonec delete "$CONTAINER_ID"
}

@test "ozonec create new namespace" {
    ozonec create -p $TEST_DIR/ozonec.pid "$CONTAINER_ID" 3>&-
    ozonec start "$CONTAINER_ID"

    local self_mnt_ns=$(readlink /proc/self/ns/mnt)
    local container_pid=$(cat $TEST_DIR/ozonec.pid)
    local container_mnt_ns=$(readlink /proc/$container_pid/ns/mnt)
    [[ "$self_mnt_ns" != "$container_mnt_ns" ]]
}

@test "ozonec join existed namespace" {
    ozonec create -p $TEST_DIR/fst.pid "$CONTAINER_ID" 3>&-
    ozonec start "$CONTAINER_ID"
    local fst_container_pid=$(cat $TEST_DIR/fst.pid)
    local fst_pid_ns=$(readlink /proc/$fst_container_pid/ns/pid)

    update_config '.linux.namespaces |= [{
            type: "pid",
            path: "'/proc/$fst_container_pid/ns/pid'"
        }, {
            type: "mount"
        }]'
    local sec_container_id=$(uuidgen)
    ozonec create -p $TEST_DIR/second.pid "$sec_container_id" 3>&-
    ozonec start "$sec_container_id"
    local sec_container_pid=$(cat $TEST_DIR/second.pid)
    local sec_pid_ns=$(readlink /proc/$sec_container_pid/ns/pid)
    ozonec kill "$sec_container_id" 9
    ozonec delete "$sec_container_id"
    [[ "$fst_pid_ns" == "$sec_pid_ns" ]]
}