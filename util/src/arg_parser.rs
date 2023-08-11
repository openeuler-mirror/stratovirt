// Copyright (c) 2020 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::cmp::PartialEq;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::env;
use std::io::Write;
use std::process;

use anyhow::{anyhow, bail, Result};

use crate::UtilError;

const PREFIX_CHARS_SHORT: &str = "-";
const PREFIX_CHARS_LONG: &str = "-";
const PREFIX_OPT_LONG: &str = "--";
const ARG_SEPARATOR: &str = "--";
const HELP_SHORT: &str = "h";
const HELP_LONG: &str = "help";
const VERSION_SHORT: &str = "V";
const VERSION_LONG: &str = "version";
const FOUR_BLANK: &str = "    ";
const EIGHT_BLANK: &str = "        ";
const TWENTY_FOUT_BLANK: &str = "                        ";

type ArgsMap = BTreeMap<String, Vec<String>>;

/// Format help type.
#[derive(PartialEq, Eq, Debug)]
pub enum HelpType {
    /// Argument as a Flag.
    Flags,
    /// Argument as a Option.
    Optional,
    /// Argument will not output in help message.
    Hidden,
}

/// Structure to store `ArgParser` information, which contains a command line
/// program and all command line arguments can be used. The `ArgParser` are set
/// using the `ArgParser::get_matches` member methods to start parse process
/// cmdline.
///
/// # Examples
///
/// ```no_run
/// # use util::arg_parser::{ArgParser, Arg};
/// let application = ArgParser::new("My Application")
///     .author("example")
///     .version("0.0.1")
///     .about("Description for application")
///     .arg(Arg::with_name("arg_name"))
///     .get_matches();
/// ```
#[derive(Clone, Debug, Default)]
pub struct ArgParser<'a> {
    name: &'a str,
    version: Option<&'a str>,
    author: Option<&'a str>,
    about: Option<&'a str>,
    args: BTreeMap<&'a str, Arg<'a>>,
    allow_list: Vec<String>,
}

/// The structure is used to get information about arguments that were supplied
/// to the application from user. New instances of this struct are created by
/// using the `ArgParser::get_matches` methods.
#[derive(Debug, Default, Clone)]
pub struct ArgMatches<'a> {
    pub args: BTreeMap<&'a str, Arg<'a>>,
    pub extra_args: Vec<String>,
}

/// The structure of a command line argument. Used to set all the options that
/// define a valid argument for the application.
///
/// # Examples
///
/// ```rust
/// # use util::arg_parser::Arg;
/// let arg = Arg::with_name("name")
///     .long("name")
///     .value_name("arg_name")
///     .help("set the name of the arg.")
///     .takes_value(true);
/// ```
#[derive(Clone, Debug, Default)]
pub struct Arg<'a> {
    name: &'a str,
    long: Option<&'a str>,
    short: Option<&'a str>,
    opt_long: Option<&'a str>,
    help: Option<&'a str>,
    value_name: Option<&'a str>,
    value: Option<String>,
    values: Option<Vec<String>>,
    possible_values: Option<Vec<&'a str>>,
    required: bool,
    presented: bool,
    hiddable: bool,
    multiple: bool,
    can_no_value: bool,
}

impl<'a> ArgParser<'a> {
    /// Create a new `ArgParser` with a name. The name will be displayed to the
    /// user when they use `-V` or `-h`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use util::arg_parser::ArgParser;
    ///
    /// let application = ArgParser::new("My Application");
    /// ```
    pub fn new(name: &'a str) -> Self {
        let mut arg_parser = ArgParser::default().name(name);

        arg_parser
            .allow_list
            .push(format!("{}{}", PREFIX_CHARS_SHORT, HELP_SHORT));
        arg_parser
            .allow_list
            .push(format!("{}{}", PREFIX_CHARS_LONG, HELP_LONG));
        arg_parser
            .allow_list
            .push(format!("{}{}", PREFIX_CHARS_SHORT, VERSION_SHORT));
        arg_parser
            .allow_list
            .push(format!("{}{}", PREFIX_CHARS_LONG, VERSION_LONG));

        arg_parser
    }

    /// Set name for ArgParser.
    fn name(mut self, name: &'a str) -> Self {
        self.name = name;
        self
    }

    /// Set version for `ArgParser`.
    pub fn version(mut self, version: &'a str) -> Self {
        self.version = Some(version);
        self
    }

    /// Set author for `ArgParser`.
    pub fn author(mut self, author: &'a str) -> Self {
        self.author = Some(author);
        self
    }

    /// Set about for `ArgParser`.
    pub fn about(mut self, about: &'a str) -> Self {
        self.about = Some(about);
        self
    }

    /// Insert a new arg into `ArgParser`'s `args`.
    pub fn arg(mut self, arg: Arg<'a>) -> Self {
        if arg.long.is_some() {
            self.allow_list
                .push(format!("{}{}", PREFIX_CHARS_LONG, arg.long.unwrap()));
        }
        if arg.short.is_some() {
            self.allow_list
                .push(format!("{}{}", PREFIX_CHARS_SHORT, arg.short.unwrap()));
        }
        if arg.opt_long.is_some() {
            self.allow_list
                .push(format!("{}{}", PREFIX_OPT_LONG, arg.opt_long.unwrap()));
        }
        self.args.insert(arg.name, arg);
        self
    }

    /// Starts the parsing process.This method gets all user provided arguments
    /// from [`env::args_os`] in order to allow for invalid UTF-8 code points.
    pub fn get_matches(mut self) -> Result<ArgMatches<'a>> {
        let cmd_args: Vec<String> = env::args().collect();
        let (arg_hash, multi_vec, sub_str) = parse_cmdline(&cmd_args, &self.allow_list)?;

        if arg_hash.contains_key(HELP_SHORT) || arg_hash.contains_key(HELP_LONG) {
            self.output_help(&mut std::io::stdout());
            process::exit(0);
        }

        if arg_hash.contains_key(VERSION_SHORT) || arg_hash.contains_key(VERSION_LONG) {
            self.show_version();
            process::exit(0);
        }

        for arg in self.args.values_mut() {
            (*arg).parse_from_hash(&arg_hash, &multi_vec)?;
        }

        Ok(ArgMatches::new(self.args, sub_str))
    }

    fn output_help(&self, handle: &mut dyn Write) {
        let mut output_base: Vec<String> = Vec::new();
        let mut output_flags: Vec<String> = Vec::new();
        let mut output_options: Vec<String> = Vec::new();

        // help base output
        output_base.push(format!("{} {}", self.name, self.version.unwrap_or("")));
        output_base.push(self.author.unwrap_or("").to_string());
        output_base.push(self.about.unwrap_or("").to_string());

        // Default FLAGS
        output_flags.push(format!(
            "{}{}h, {}help           Prints help information",
            FOUR_BLANK, PREFIX_CHARS_SHORT, PREFIX_CHARS_LONG
        ));
        output_flags.push(format!(
            "{}{}V, {}version        Prints version information",
            FOUR_BLANK, PREFIX_CHARS_SHORT, PREFIX_CHARS_LONG
        ));

        // FLAGS and OPTIONS
        for arg in self.args.values() {
            let (help_str, help_type) = (*arg).help_message();
            match help_type {
                HelpType::Flags => {
                    output_flags.push(help_str);
                }
                HelpType::Optional => {
                    output_options.push(help_str);
                }
                HelpType::Hidden => {}
            }
        }

        // base output
        for line in output_base {
            writeln!(handle, "{}", line).unwrap();
        }

        // USAGE output
        writeln!(handle, "USAGE:").unwrap();
        if output_options.is_empty() {
            writeln!(handle, "{}{} [FLAGS]", FOUR_BLANK, get_name()).unwrap();
        } else {
            writeln!(handle, "{}{} [FLAGS] [OPTIONS]", FOUR_BLANK, get_name()).unwrap();
        }

        // FLAGS output
        writeln!(handle, "FLAGS:").unwrap();
        for line in output_flags {
            writeln!(handle, "{}", line).unwrap();
        }

        // OPTIONS output
        if !output_options.is_empty() {
            writeln!(handle, "OPTIONS:").unwrap();
            for line in output_options {
                writeln!(handle, "{}", line).unwrap();
            }
        }
    }

    fn show_version(&self) {
        let stdout = std::io::stdout();
        let mut handle = std::io::BufWriter::new(stdout);
        writeln!(
            handle,
            "{} {}",
            self.name,
            self.version.unwrap_or("Unknown")
        )
        .unwrap();
    }
}

impl<'a> Arg<'a> {
    /// Create a new arg with arg's name.
    pub fn with_name(name: &'a str) -> Self {
        Arg {
            name,
            ..Default::default()
        }
    }

    /// Set long argument for arg.
    pub fn long(mut self, long: &'a str) -> Self {
        self.long = Some(long);
        self
    }

    /// Set short argument for arg.
    pub fn short(mut self, short: &'a str) -> Self {
        self.short = Some(short);
        self
    }

    /// Set opt long argument for arg.
    pub fn opt_long(mut self, opt_long: &'a str) -> Self {
        self.opt_long = Some(opt_long);
        self
    }

    /// Set help message for arg.
    pub fn help(mut self, help: &'a str) -> Self {
        self.help = Some(help);
        self
    }

    /// Set hidden, it can hid help message for this argument.
    pub fn hidden(mut self, hidden: bool) -> Self {
        self.hiddable = hidden;
        self
    }

    /// Set multiple, it can allow use argument more than once.
    pub fn multiple(mut self, multiple: bool) -> Self {
        self.multiple = multiple;
        self
    }

    /// Set value_name for help message.
    pub fn value_name(mut self, value_name: &'a str) -> Self {
        self.value_name = Some(value_name);
        self
    }

    /// Set value kind for arguments.
    pub fn takes_value(mut self, switch: bool) -> Self {
        if switch {
            self.value = Some(Default::default());
        }
        self
    }

    /// Set value kind for arguments.
    pub fn takes_values(mut self, switch: bool) -> Self {
        if switch {
            self.values = Some(Vec::new());
        }
        self
    }

    /// Set required for arguments.
    pub fn required(mut self, required: bool) -> Self {
        self.required = required;
        self
    }

    /// Set can no value for arguments.
    pub fn can_no_value(mut self, can: bool) -> Self {
        self.can_no_value = can;
        self
    }

    /// Set default value for a argument.
    pub fn default_value(mut self, value: &'a str) -> Self {
        match self.value {
            Some(_) => self.value = Some(value.to_string()),
            None => {
                if self.values.is_some() {
                    let values: Vec<String> = vec![value.to_string()];
                    self.values = Some(values);
                }
            }
        }
        self.presented = true;
        self
    }

    /// Set possible values for argument.
    pub fn possible_values(mut self, values: Vec<&'a str>) -> Self {
        self.possible_values = Some(values);
        self
    }

    /// Parse argument from a hashset.
    fn parse_from_hash(&mut self, arg_hash: &ArgsMap, multi_vec: &[String]) -> Result<()> {
        let name = if let Some(long) = self.long {
            long.to_string()
        } else if let Some(opt_long) = self.opt_long {
            opt_long.to_string()
        } else {
            bail!("Invalid argument, long and opt_long are None")
        };

        if arg_hash.contains_key(&name) {
            if !self.multiple && multi_vec.contains(&name) {
                return Err(anyhow!(UtilError::DuplicateArgument(name)));
            }

            if self.value.is_some() && (arg_hash[&name].len() > 1) && !self.multiple {
                return Err(anyhow!(UtilError::DuplicateValue(name)));
            }

            if (self.value.is_some() || self.values.is_some()) && (arg_hash[&name].is_empty()) {
                if self.can_no_value {
                    self.value = Some(Default::default());
                    self.presented = true;
                    return Ok(());
                } else {
                    return Err(anyhow!(UtilError::MissingValue(name)));
                }
            }

            if (self.value.is_none() && self.values.is_none()) && (!arg_hash[&name].is_empty()) {
                return Err(anyhow!(UtilError::IllegelValue(
                    arg_hash[&name][0].to_string(),
                    name.to_string(),
                )));
            }

            if self.value.is_some() {
                if self.possible_value_check(&arg_hash[&name][0]) {
                    self.value = Some(arg_hash[&name][0].clone());
                } else {
                    return Err(anyhow!(UtilError::ValueOutOfPossible(
                        name,
                        format!("{:?}", self.possible_values),
                    )));
                }
            } else if self.values.is_some() {
                if self.possible_values_check(arg_hash[&name].clone()) {
                    self.values = Some(arg_hash[&name].clone());
                } else {
                    return Err(anyhow!(UtilError::ValueOutOfPossible(
                        name,
                        format!("{:?}", self.possible_values),
                    )));
                }
            }

            self.presented = true;
        } else if self.required {
            return Err(anyhow!(UtilError::MissingArgument(name)));
        }

        if self.short.is_some() {
            let short_name = self.short.unwrap();
            if arg_hash.contains_key(short_name) {
                if (self.value.is_none() && self.values.is_none())
                    && (!arg_hash[short_name].is_empty())
                {
                    return Err(anyhow!(UtilError::IllegelValue(
                        arg_hash[short_name][0].to_string(),
                        short_name.to_string(),
                    )));
                }

                self.presented = true;
            } else if self.required {
                return Err(anyhow!(UtilError::MissingArgument(short_name.to_string())));
            }
        }

        Ok(())
    }

    /// Produce help message for argument.
    fn help_message(&self) -> (String, HelpType) {
        let mut help_str;

        if self.hiddable {
            return (String::new(), HelpType::Hidden);
        }

        if self.short.is_some() {
            let font_str = format!(
                "{}{}{}, {}{}",
                FOUR_BLANK,
                PREFIX_CHARS_SHORT,
                self.short.unwrap(),
                PREFIX_CHARS_LONG,
                self.long.unwrap_or("")
            );
            help_str = format!("{}{}", TWENTY_FOUT_BLANK, self.help.unwrap_or(""));
            let font_offset = font_str.len();
            help_str.replace_range(..font_offset, &font_str);
            return (help_str, HelpType::Flags);
        }

        if self.long.is_some() || self.opt_long.is_some() {
            let font_str = if self.long.is_some() {
                if self.values.is_some() {
                    format!(
                        "{}{}{} {}...",
                        EIGHT_BLANK,
                        PREFIX_CHARS_LONG,
                        self.long.unwrap(),
                        self.value_name.unwrap_or(self.name)
                    )
                } else {
                    format!(
                        "{}{}{} {}",
                        EIGHT_BLANK,
                        PREFIX_CHARS_LONG,
                        self.long.unwrap(),
                        self.value_name.unwrap_or(self.name)
                    )
                }
            } else {
                format!(
                    "{}{}{}={}",
                    EIGHT_BLANK,
                    PREFIX_OPT_LONG,
                    self.opt_long.unwrap(),
                    self.value_name.unwrap_or(self.name)
                )
            };
            help_str = format!(
                "{}{}{}{}",
                TWENTY_FOUT_BLANK,
                TWENTY_FOUT_BLANK,
                TWENTY_FOUT_BLANK,
                self.help.unwrap_or("")
            );
            let font_offset = font_str.len();
            if font_offset > TWENTY_FOUT_BLANK.len() * 3 - FOUR_BLANK.len() {
                help_str = format!("{}\n{}", font_str, help_str);
            } else {
                help_str.replace_range(..font_offset, &font_str);
            }
            return (help_str, HelpType::Optional);
        }

        (String::new(), HelpType::Hidden)
    }

    fn possible_value_check(&self, value: &'a str) -> bool {
        if self.possible_values.is_some() {
            self.possible_values.as_ref().unwrap().contains(&value)
        } else {
            true
        }
    }

    fn possible_values_check(&self, values: Vec<String>) -> bool {
        if self.possible_values.is_some() {
            for value in values {
                if !self.possible_value_check(&value) {
                    return false;
                }
            }
            true
        } else {
            true
        }
    }
}

impl<'a> ArgMatches<'a> {
    fn new(args: BTreeMap<&'a str, Arg<'a>>, extra_args: Vec<String>) -> Self {
        ArgMatches { args, extra_args }
    }

    /// Get the single value for `arg`.
    ///
    /// # Arguments
    ///
    /// * `arg_name` - Name of `arg`.
    pub fn value_of(&self, arg_name: &'a str) -> Option<String> {
        match self.args.get(arg_name) {
            Some(arg) => {
                if arg.presented {
                    arg.value.clone()
                } else {
                    None
                }
            }
            None => None,
        }
    }

    /// Get the all values for `arg`.
    ///
    /// # Arguments
    ///
    /// * `arg_name` - Name of `arg`.
    pub fn values_of(&self, arg_name: &'a str) -> Option<Vec<String>> {
        match self.args.get(arg_name) {
            Some(arg) => {
                if arg.presented {
                    arg.values.clone()
                } else {
                    None
                }
            }
            None => None,
        }
    }

    /// Confirm whether the `arg` is given or not.
    ///
    /// # Arguments
    ///
    /// * `arg_name` - Name of `arg`.
    pub fn is_present(&self, arg_name: &'a str) -> bool {
        self.args[arg_name].presented
    }

    fn split_arg(args: &[String]) -> (&[String], &[String]) {
        if let Some(index) = args.iter().position(|arg| arg == ARG_SEPARATOR) {
            return (&args[..index], &args[index + 1..]);
        }
        (args, &[])
    }

    pub fn extra_args(&self) -> Vec<String> {
        self.extra_args.clone()
    }
}

fn parse_cmdline(
    cmd_args: &[String],
    allow_list: &[String],
) -> Result<(ArgsMap, Vec<String>, Vec<String>)> {
    let (cmd_args, sub_args) = ArgMatches::split_arg(cmd_args);
    let mut arg_map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut multi_vec: Vec<String> = Vec::new();

    let mut i = (0, "");
    let mut j = 1;
    for cmd_arg in &cmd_args[1..] {
        if !allow_list.contains(cmd_arg)
            && cmd_arg.starts_with(PREFIX_CHARS_SHORT)
            && !cmd_arg.starts_with(PREFIX_OPT_LONG)
        {
            return Err(anyhow!(UtilError::UnexpectedArguments(cmd_arg.to_string())));
        }

        if cmd_arg.starts_with(PREFIX_OPT_LONG) {
            let splits = cmd_arg.split('=').collect::<Vec<&str>>();
            // It has two arguments. e.g. "--modcaps=+sys_admin".
            if splits.len() != 2 {
                return Err(anyhow!(UtilError::UnexpectedArguments(cmd_arg.to_string())));
            }
            if !allow_list.contains(&splits[0].to_string()) {
                return Err(anyhow!(UtilError::UnexpectedArguments(cmd_arg.to_string())));
            }
            let arg_str = split_arg(splits[0], PREFIX_OPT_LONG);
            if let Entry::Vacant(e) = arg_map.entry(arg_str.to_string()) {
                e.insert(Vec::new());
            } else {
                multi_vec.push(arg_str.to_string());
            }
            arg_map
                .get_mut(arg_str.as_str())
                .unwrap()
                .push(splits[1].to_string());
        } else if cmd_arg.starts_with(PREFIX_CHARS_LONG) {
            let arg_str = split_arg(cmd_arg, PREFIX_CHARS_LONG);

            if let Entry::Vacant(e) = arg_map.entry(arg_str.clone()) {
                e.insert(Vec::new());
            } else {
                multi_vec.push(arg_str);
            }

            i = (j, PREFIX_CHARS_LONG);
        } else if cmd_arg.starts_with(PREFIX_CHARS_SHORT) {
            let arg_str = split_arg(cmd_arg, PREFIX_CHARS_SHORT);

            if let Entry::Vacant(e) = arg_map.entry(arg_str.clone()) {
                e.insert(Vec::new());
            } else {
                multi_vec.push(arg_str);
            }
            i = (j, PREFIX_CHARS_SHORT);
        } else {
            let arg_str = match i.1 {
                PREFIX_CHARS_LONG => split_arg(&cmd_args[i.0], PREFIX_CHARS_LONG),
                &_ => {
                    return Err(anyhow!(UtilError::UnexpectedArguments(cmd_arg.to_string())));
                }
            };
            arg_map
                .get_mut(arg_str.as_str())
                .unwrap()
                .push(cmd_arg.to_string());
        }
        j += 1;
    }
    Ok((arg_map, multi_vec, sub_args.to_vec()))
}

fn get_name() -> String {
    let cmd_args: Vec<String> = env::args().collect();
    let name_str: Vec<&str> = cmd_args[0].split('/').collect();
    (*name_str.last().unwrap()).to_string()
}

fn split_arg(arg: &str, prefix_chars: &str) -> String {
    let i = prefix_chars.len();
    String::from(&arg[i..])
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Seek, SeekFrom};

    use super::*;

    #[derive(Default)]
    struct TestBuffer {
        inner: Cursor<Vec<u8>>,
    }

    impl TestBuffer {
        fn get_msg_vec(&mut self) -> String {
            self.inner.seek(SeekFrom::Start(0)).unwrap();
            let mut msgs = Vec::new();
            self.inner.read_to_end(&mut msgs).unwrap();
            String::from_utf8(msgs).unwrap()
        }
    }

    fn create_test_arg<'a>() -> ArgParser<'a> {
        ArgParser::new("StratoVirt")
            .version("1.0.0")
            .author("Huawei Technologies Co., Ltd")
            .about("A light kvm-based hypervisor.")
            .arg(
                Arg::with_name("name")
                    .long("name")
                    .value_name("vm_name")
                    .help("set the name of the guest.")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name("qmp")
                    .long("qmp")
                    .value_name("unix:PATH")
                    .help("set qmp's unixsocket path")
                    .takes_value(true)
                    .required(true),
            )
            .arg(
                Arg::with_name("drive")
                    .multiple(true)
                    .long("drive")
                    .value_name("[file=path][,id=str][,readonly=][,direct=]")
                    .help("use 'file' as a drive image")
                    .takes_values(true),
            )
            .arg(
                Arg::with_name("display log")
                    .long("D")
                    .value_name("log_path")
                    .help("output log to logfile (default stderr)")
                    .takes_value(true)
                    .can_no_value(true),
            )
            .arg(
                Arg::with_name("freeze_cpu")
                    .short("S")
                    .long("freeze")
                    .help("Freeze CPU at startup")
                    .takes_value(false)
                    .required(false),
            )
    }

    fn create_test_arg_matches(cmdline_str: &str) -> ArgMatches {
        let mut arg_parser = create_test_arg();
        let input_vec = cmdline_str
            .split(' ')
            .collect::<Vec<&str>>()
            .iter_mut()
            .map(|item| item.to_string())
            .collect::<Vec<String>>();
        let (arg_hash, multi_vec, sub_str) =
            parse_cmdline(&input_vec, &arg_parser.allow_list).unwrap();
        for arg in arg_parser.args.values_mut() {
            assert!((*arg).parse_from_hash(&arg_hash, &multi_vec).is_ok());
        }
        ArgMatches::new(arg_parser.args, sub_str)
    }

    #[test]
    fn test_arg_base_msg() {
        let arg_parser = create_test_arg();
        assert_eq!(arg_parser.name, "StratoVirt");
        assert_eq!(arg_parser.version.unwrap(), "1.0.0");
        assert_eq!(arg_parser.author.unwrap(), "Huawei Technologies Co., Ltd");
        assert_eq!(arg_parser.about.unwrap(), "A light kvm-based hypervisor.");
    }

    #[test]
    fn test_arg_base_help_msg() {
        let arg_parser = create_test_arg();
        let mut buffer = TestBuffer::default();
        arg_parser.output_help(&mut buffer.inner);

        let help_str = buffer.get_msg_vec();
        let help_msg = help_str.split("\n").collect::<Vec<&str>>();
        assert_eq!(help_msg[0], "StratoVirt 1.0.0");
        assert_eq!(help_msg[1], "Huawei Technologies Co., Ltd");
        assert_eq!(help_msg[2], "A light kvm-based hypervisor.");
        assert_eq!(help_msg[3], "USAGE:");
        assert_eq!(help_msg[5], "FLAGS:");
        assert_eq!(help_msg[9], "OPTIONS:");
    }

    #[test]
    fn test_single_arg_check() {
        let arg = Arg::with_name("name")
            .long("name")
            .short("N")
            .value_name("vm_name")
            .help("set the name of the guest.")
            .takes_value(true)
            .possible_values(vec!["vm1", "vm2", "vm3"])
            .required(false)
            .hidden(false)
            .multiple(false)
            .can_no_value(false)
            .default_value("vm1");
        assert_eq!(arg.name, "name");
        assert_eq!(arg.long.unwrap(), "name");
        assert_eq!(arg.short.unwrap(), "N");
        assert_eq!(arg.value_name.unwrap(), "vm_name");
        assert_eq!(arg.help.unwrap(), "set the name of the guest.");
        assert_eq!(
            arg.possible_values.as_ref().unwrap(),
            &vec!["vm1", "vm2", "vm3"]
        );
        assert_eq!(arg.required, false);
        assert_eq!(arg.presented, true);
        assert_eq!(arg.hiddable, false);
        assert_eq!(arg.can_no_value, false);
        assert_eq!(arg.value.as_ref().unwrap(), "vm1");

        let (help_msg, help_type) = arg.help_message();
        assert_eq!(help_type, HelpType::Flags);
        assert_eq!(
            help_msg,
            format!(
                "{}-N, -name{}   set the name of the guest.",
                FOUR_BLANK, EIGHT_BLANK
            )
        );
    }

    #[test]
    fn test_arg_matches() {
        let arg_matches = create_test_arg_matches(
            "stratovirt -name vm1 -qmp unix:sv.sock -drive file=/path/to/rootfs,id=rootfs -D -S",
        );

        assert!(arg_matches.is_present("name"));
        assert!(arg_matches.is_present("qmp"));
        assert!(arg_matches.is_present("drive"));
        assert!(arg_matches.is_present("display log"));
        assert!(arg_matches.is_present("freeze_cpu"));

        assert_eq!(arg_matches.value_of("name").as_ref().unwrap(), "vm1");
        assert_eq!(
            arg_matches.value_of("qmp").as_ref().unwrap(),
            "unix:sv.sock"
        );
        assert_eq!(
            arg_matches.values_of("drive").as_ref().unwrap(),
            &vec!["file=/path/to/rootfs,id=rootfs"]
        );
    }
}
