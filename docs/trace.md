# Tracing

This document describes the way for debugging and profiling in StratoVirt and how
to use it.

## Add trace

### Modify configuration file

First, you need to modify or crate toml file in the trace/trace_info directory to
add a new event or scope in order to generate the trace function. For example:

```toml
[[events]]
name = "virtio_receive_request"
args = "device: String, behaviour: String"
message = "{}: Request received from guest {}, ready to start processing."
enabled = true

[[scopes]]
name = "update_cursor"
args = ""
message = ""
enabled = true
```

In the above configuration, "name" is used to represent the only trace, and
duplication is not allowed; "message" and "args" will be formatted as information
output by trace; "enabled" indicates whether it is enabled during compilation.

### Call trace function

Just call the trace function where needed.
```rust
fn process_queue(&mut self) -> Result<()> {
    trace::virtio_receive_request("Rng".to_string(), "to IO".to_string());
    let mut queue_lock = self.queue.lock().unwrap();
    let mut need_interrupt = false;
    ......
}

fn update_cursor(&mut self, info_cursor: &VirtioGpuUpdateCursor, hdr_type: u32) -> Result<()> {
    // Trace starts from here, and end when it leaves this scope
    trace::trace_scope_start!(update_cursor);
    ......
}
```

## Trace control interface

Trace state in StratoVirt are disabled by default. Users can control whether
the trace state is enabled through the command line or qmp command.

### Command line
Before starting, you can prepare the trace list that needs to be enabled
and pass it to StratoVirt through [-trace](config_guidebook.md#3-trace).

### QMP
During the running, you can send the [trace-set-state](qmp.md#trace-set-state)
command through the qmp socket to enable or disable trace state. Similarly,
using the [trace-get-state](qmp.md#trace-get-state) command can check
whether the setting is successful.

## Choose trace backends

By setting different features during compilation, trace can generate specified
code to support different trace tools. StratoVirt currently supports two kinds
of settings.

### log

StratoVirt supports outputting trace to the log file at trace level. Turn on
the **trace_to_logger** feature to use is.

### Ftrace

Ftrace is a tracer provided by Linux kernel, which can help linux developers to
debug or analyze issues. As ftrace can avoid performance penalty, it's especially
suited for performance issues.

It can be enabled by turning on the **trace_to_ftrace** feature during compilation.
StratoVirt use ftrace by writing trace data to ftrace marker, and developers can
read trace records from trace file under mounted ftrace director,
e.g. /sys/kernel/debug/tracing/trace.

### HiTraceMeter

HiTraceMeter(https://gitee.com/openharmony/hiviewdfx_hitrace) is tool used by developers
to trace process and measure performance. Based on the Ftrace, it provides the ability
to measure the execution time of user-mode application code. After turning on the
**trace_to_hitrace** feature, it can be used on HarmonyOS.
