# Tracing

This document describes the way for debugging and profiling in StratoVirt and how
to use it.

## Ftrace

Ftrace is a tracer provided by Linux kernel, which can help linux developers to
debug or analyze issues. As ftrace can avoid performance penalty, it's especially
suited for performance issues.

StratoVirt use ftrace by writing trace data to ftrace marker, and developers can
read trace records from *trace* file under mounted ftrace director,
e.g. /sys/kernel/debug/tracing/trace.

## How to use

Trace events are put in StratoVirt by the macro *ftrace!*. The first parameter the
macro receives is name of the trace event. Remaining parameters the macro receives
are the same as *println!* or *format!*, i.e. the first parameter is a format string,
and additional parameters passed replace the {}s within the format string.

```rust
#[macro_use]
extern crate util;

fn trace_example() {
    ftrace!(trace_example, "Test for tracer.");
}
```

Trace events in StratoVirt are disabled by default. Users can pass the file listing
enabled events by launching StratoVirt with "-trace events=<file>". The file should
contains one event name per line.
