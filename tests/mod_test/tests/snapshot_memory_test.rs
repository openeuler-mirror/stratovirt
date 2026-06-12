// Copyright (c) 2026 Huawei Technologies Co.,Ltd. All rights reserved.
//
// StratoVirt is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use mod_test::libtest::{test_init, MACHINE_TYPE_ARG};

fn assert_return(value: &serde_json::Value) {
    assert!(
        value.get("return").is_some(),
        "unexpected QMP response: {value}"
    );
}

fn create_dummy_kernel() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "stratovirt-snapshot-memory-{}.kernel",
        std::process::id()
    ));
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(10 * 1024 * 1024).unwrap();
    path
}

/// Query snapshot memory metadata through QMP.
///
/// TestStep:
///   1. Start a VM with the test accelerator.
///   2. Pause the VM.
///   3. Query cold resident/empty page state.
///   4. Query stable memory mappings.
/// Expect:
///   1/2/3/4: success.
#[test]
#[ignore = "requires STRATOVIRT_BINARY and a host that can start the test accelerator"]
fn snapshot_memory_query_workflow() {
    let kernel_path = create_dummy_kernel();
    let args = format!(
        "{} -m 128 -kernel {}",
        MACHINE_TYPE_ARG,
        kernel_path.display()
    );
    let ts = test_init(args.split(' ').collect());

    assert_return(&ts.qmp(r#"{"execute":"stop"}"#));
    ts.wait_qmp_event();

    let page_state = ts.qmp(r#"{"execute":"query-mem-page-state"}"#);
    assert!(page_state["return"]["resident"].is_array());
    assert!(page_state["return"]["empty"].is_array());
    assert!(page_state["return"]["page-size"].is_u64());

    let mappings = ts.qmp(r#"{"execute":"query-mem-mappings"}"#);
    assert!(mappings["return"]["mappings"].is_array());

    drop(ts);
    let _ = std::fs::remove_file(kernel_path);
}
