#! /usr/bin/env bats

load helpers

setup_file()
{
    setup_bundle
}

setup()
{
    CONTAINER_ID=$(uuidgen)
    setup_pty_server
}

teardown()
{
    ozonec kill "$CONTAINER_ID" 9
    ozonec delete "$CONTAINER_ID"
    killall -9 pty-server
    rm -f $TEST_DIR/console*
}

@test "ozonec with bind mount" {
    update_config '.mounts += [{
            source: ".",
            destination: "/tmp/rbind",
            options: ["rbind"]
        }]'

    ozonec create "$CONTAINER_ID" 3>&-
    ozonec start "$CONTAINER_ID"
    ozonec exec -t --console-socket "$CONSOLE_PATH" "$CONTAINER_ID" -- ls /tmp/rbind/config.json
    run sed -n '1p' $TEST_DIR/console.log
    [[ ${lines[0]} == *"/tmp/rbind/config.json"* ]]
}

@test "ozonec mount /proc" {
    ozonec create "$CONTAINER_ID" 3>&-
    ozonec start "$CONTAINER_ID"
    ozonec exec -t --console-socket "$CONSOLE_PATH" "$CONTAINER_ID" -- grep "^proc /proc proc " /proc/mounts
    run sed -n '1p' $TEST_DIR/console.log
    [[ ${lines[0]} == *"proc /proc proc "* ]]
}

@test "ozonec mount /sys" {
    ozonec create "$CONTAINER_ID" 3>&-
    ozonec start "$CONTAINER_ID"
    ozonec exec -t --console-socket "$CONSOLE_PATH" "$CONTAINER_ID" -- grep "^sysfs /sys sysfs " /proc/mounts
    run sed -n '1p' $TEST_DIR/console.log
    [[ ${lines[0]} == *"sysfs /sys "*"ro"*"nosuid"*"nodev"*"noexec"* ]]
}

@test "ozonec mount /dev/pts" {
    ozonec create "$CONTAINER_ID" 3>&-
    ozonec start "$CONTAINER_ID"
    ozonec exec -t --console-socket "$CONSOLE_PATH" "$CONTAINER_ID" -- grep "^devpts /dev/pts devpts " /proc/mounts
    run sed -n '1p' $TEST_DIR/console.log
    [[ ${lines[0]} == *"devpts /dev/pts devpts "*"nosuid"*"noexec"*"gid=5"*"mode=620"*"ptmxmode=666"* ]]
}

@test "ozonec mount /dev/shm" {
    ozonec create "$CONTAINER_ID" 3>&-
    ozonec start "$CONTAINER_ID"
    ozonec exec -t --console-socket "$CONSOLE_PATH" "$CONTAINER_ID" -- grep "^shm /dev/shm tmpfs" /proc/mounts
    run sed -n '1p' $TEST_DIR/console.log
    [[ ${lines[0]} == *"/dev/shm tmpfs "*"nosuid"*"nodev"*"noexec"*"size=65536k"* ]]
}

@test "ozonec default devices" {
    ozonec create "$CONTAINER_ID" 3>&-
    ozonec start "$CONTAINER_ID"

    ozonec exec -t --console-socket "$CONSOLE_PATH" "$CONTAINER_ID" -- ls -al /dev/
    run grep -w "null" $TEST_DIR/console.log
    [[ $status -eq 0 ]]
    run grep -w "zero" $TEST_DIR/console.log
    [[ $status -eq 0 ]]
    run grep -w "full" $TEST_DIR/console.log
    [[ $status -eq 0 ]]
    run grep -w "random" $TEST_DIR/console.log
    [[ $status -eq 0 ]]
    run grep -w "urandom" $TEST_DIR/console.log
    [[ $status -eq 0 ]]
    run grep -w "tty" $TEST_DIR/console.log
    [[ $status -eq 0 ]]
    run grep -w "console" $TEST_DIR/console.log
    [[ $status -ne 0 ]]
    run grep -w "console" $TEST_DIR/console.log
    [[ $status -ne 0 ]]

    rm -f $TEST_DIR/console.log
    ozonec exec -t --console-socket "$CONSOLE_PATH" "$CONTAINER_ID" -- ls -al /dev/pts/ptmx
    run grep -w "/dev/pts/ptmx" $TEST_DIR/console.log
    [[ $status -ne 0 ]]
}

@test "ozonec create /dev/console" {
    update_config '.process.terminal = true'
    update_config '.process.args = ["ls", "/dev/console"]'
    ozonec create --console-socket "$CONSOLE_PATH" "$CONTAINER_ID" 3>&-
    ozonec start "$CONTAINER_ID"

    cat $TEST_DIR/console.log
    run sed -n '1p' $TEST_DIR/console.log
    [[ ${lines[0]} == *"/dev/console"* ]]
}