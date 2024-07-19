# HiSysEvent

HiSysEvent(https://gitee.com/openharmony/hiviewdfx_hisysevent) is a tool in open-
harmonyOS to recode important information of key processes during system running,
helping locate faults and do some data analytics.

This document describes the way to how to use hisysevent in StratoVirt.

## Add Event

### Modify configuration file

First, you need to modify or creat toml file in the event/event_info directory
to add a new event in order to generate the event function. For example:

```toml
[[events]]
name = "example"
event_type = "Behavior"
args = "example_bool: bool, example_str: String, example_integer: u64, example_array: &[u8]"
enable = true
```

In the above configuration, "name" is used to represent the only event, and
duplication is not allowed; "event_type" is one of four event type defined
by openharmonyOS: Fault, Statistic, Security and Behavior; "args" will be
formatted as arguments passed to hisysevent service in open-harmonyOS;
"enabled" indicates whether it is enabled during compilation.

### Call event function

Just call the event function where needed.
```rust
fn init_machine_ram(&self, sys_mem: &Arc<AddressSpace>, mem_size: u64) -> Result<()> {    
    hisysevent::example("true", "init_ram".to_string(), mem_size, &[0,1]);
    let vm_ram = self.get_vm_ram();
    let layout_size = MEM_LAYOUT[LayoutEntryType::Mem as usize].1;
    ......
}
```
