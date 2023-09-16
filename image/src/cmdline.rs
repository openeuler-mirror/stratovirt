// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::collections::HashMap;

use anyhow::{bail, Result};

enum ArgsType {
    Flag,
    Opt,
    OptMulti,
}

struct Arg {
    args_type: ArgsType,
    value: Option<String>,
    values: Vec<String>,
    // Whether this parameter was configured.
    presented: bool,
}

impl Arg {
    fn new(args_type: ArgsType) -> Self {
        Self {
            args_type,
            value: None,
            values: vec![],
            presented: false,
        }
    }
}

pub struct ArgsParse {
    args: HashMap<String, Arg>,
    pub free: Vec<String>,
}

impl ArgsParse {
    pub fn create(opt_flag: Vec<&str>, opt_short: Vec<&str>, opt_multi: Vec<&str>) -> Self {
        let mut args: HashMap<String, Arg> = HashMap::new();
        for arg_name in opt_flag {
            args.insert(arg_name.to_string(), Arg::new(ArgsType::Flag));
        }

        for arg_name in opt_short {
            args.insert(arg_name.to_string(), Arg::new(ArgsType::Opt));
        }

        for arg_name in opt_multi {
            args.insert(arg_name.to_string(), Arg::new(ArgsType::OptMulti));
        }

        Self {
            args,
            free: Vec::new(),
        }
    }

    pub fn parse(&mut self, args: Vec<String>) -> Result<()> {
        let len = args.len();
        let mut pre_opt = (0, "".to_string());

        for idx in 0..len {
            let str = args[idx as usize].clone();
            if str.starts_with("-") && str.len() > 1 {
                if pre_opt.1.len() != 0 {
                    bail!("missing argument for option '{}'", pre_opt.1);
                }

                let name = if str.starts_with("--") && str.len() > 2 {
                    (&str[2..]).to_string()
                } else if str.starts_with("-") && str.len() > 1 {
                    (&str[1..]).to_string()
                } else {
                    bail!("unrecognized option '{}'", str);
                };

                if let Some(args) = self.args.get_mut(&name) {
                    match args.args_type {
                        ArgsType::Flag => {
                            args.presented = true;
                        }
                        _ => {
                            pre_opt = (idx, name);
                        }
                    };
                } else {
                    bail!("unrecognized option '{}'", name);
                }

                continue;
            }

            if pre_opt.0 + 1 == idx && pre_opt.1.len() != 0 {
                let name = pre_opt.1.to_string();
                let value = str.to_string();
                if let Some(arg) = self.args.get_mut(&name) {
                    match arg.args_type {
                        ArgsType::Opt => {
                            arg.presented = true;
                            arg.value = Some(value);
                        }
                        ArgsType::OptMulti => {
                            arg.presented = true;
                            arg.values.push(value);
                        }
                        _ => bail!("unrecognized option '{}'", name),
                    }
                }
                pre_opt = (0, "".to_string());
            } else if pre_opt.1.len() == 0 {
                self.free.push(str.to_string());
            } else {
                bail!("unrecognized option '{}'", pre_opt.1);
            }
        }

        if pre_opt.0 == 0 && pre_opt.1.len() != 0 {
            bail!("unrecognized option '{}'", pre_opt.1);
        }

        Ok(())
    }

    pub fn opt_present(&mut self, name: &str) -> bool {
        if let Some(arg) = self.args.get(name) {
            return arg.presented;
        }
        false
    }

    pub fn opt_str(&mut self, name: &str) -> Option<String> {
        if let Some(arg) = self.args.get(name) {
            return arg.value.clone();
        }
        None
    }

    pub fn opt_strs(&mut self, name: &str) -> Vec<String> {
        let mut values: Vec<String> = vec![];
        if let Some(arg) = self.args.get(name) {
            values = arg.values.clone();
        }
        values
    }
}

#[cfg(test)]
mod test {
    use super::ArgsParse;

    #[test]
    fn test_arg_parse() {
        let mut arg_parser = ArgsParse::create(vec!["q", "h", "help"], vec!["f"], vec!["o"]);
        let cmd_line = "-f qcow2 -q -h --help -o cluster_size=512 -o refcount_bits=16 img_path +1G";
        let cmd_args: Vec<String> = cmd_line
            .split(' ')
            .into_iter()
            .map(|str| str.to_string())
            .collect();

        let ret = arg_parser.parse(cmd_args);
        println!("{:?}", ret);
        assert!(ret.is_ok());

        assert_eq!(arg_parser.opt_present("f"), true);
        assert_eq!(arg_parser.opt_present("q"), true);
        assert_eq!(arg_parser.opt_present("h"), true);
        assert_eq!(arg_parser.opt_present("help"), true);

        let values = arg_parser.opt_strs("o");
        assert!(values.contains(&"cluster_size=512".to_string()));
        assert!(values.contains(&"refcount_bits=16".to_string()));

        let free = arg_parser.free.clone();
        assert_eq!(free[0], "img_path".to_string());
        assert_eq!(free[1], "+1G".to_string());
    }
}
