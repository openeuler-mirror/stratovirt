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
    ozonec kill "$CONTAINER_ID"
    ozonec delete "$CONTAINER_ID"
    killall -9 pty-server
    rm -f $TEST_DIR/console*
}

@test "ozonec create with console socket" {
    update_config '.process.terminal = true'
    update_config '.process.args = ["ls", "-alh"]'
    ozonec create --console-socket "$CONSOLE_PATH" "$CONTAINER_ID" 3>&-

    run ozonec start "$CONTAINER_ID"
    [[ $status -eq 0 ]]
    run sed -n '1p' $TEST_DIR/console.log
    [[ ${lines[0]} == *"total "* ]]
}

@test "ozonec exec with console socket" {
    update_config '.process.terminal = false'
    update_config '.process.args = ["sleep", "3600"]'
    ozonec create "$CONTAINER_ID" 3>&-
    ozonec start "$CONTAINER_ID"

    run ozonec exec -t --console-socket "$CONSOLE_PATH" "$CONTAINER_ID" -- ls -alh
    run sed -n '1p' $TEST_DIR/console.log
    [[ ${lines[0]} == *"total "* ]]
}