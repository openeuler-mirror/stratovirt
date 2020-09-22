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

use std::collections::BTreeMap;
use std::env;
use std::io::Write;
use std::process;

use crate::errors::{ErrorKind, Result};

const PREFIX_CHARS_SHORT: &str = "-";
const PREFIX_CHARS_LONG: &str = "-";
const HELP_SHORT: &str = "h";
const HELP_LONG: &str = "help";
const VERSION_SHORT: &str = "V";
const VERSION_LONG: &str = "version";
const FOUR_BLANK: &str = "    ";
const EIGHT_BLANK: &str = "        ";
const TWENTY_FOUT_BLANK: &str = "                        ";

type ArgsMap = BTreeMap<String, Vec<String>>;

/// Format help type.
pub enum HelpType {
    /// Argument as a Flag.
    FLAGS,
    /// Argument as a Option.
    OPTION,
    /// Argument will not output in help message.
    HIDDEN,
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
///     .arg(
///         Arg::with_name("arg_name")
///     )
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
        self.args.insert(arg.name, arg);
        self
    }

    /// Starts the parsing process.This method gets all user provided arguments
    /// from [`env::args_os`] in order to allow for invalid UTF-8 code points.
    pub fn get_matches(mut self) -> Result<ArgMatches<'a>> {
        let (arg_hash, multi_vec) = parse_cmdline(&self.allow_list)?;

        if arg_hash.contains_key(HELP_SHORT) || arg_hash.contains_key(HELP_LONG) {
            self.output_help();
            process::exit(0);
        }

        if arg_hash.contains_key(VERSION_SHORT) || arg_hash.contains_key(VERSION_LONG) {
            self.show_version();
            process::exit(0);
        }

        for arg in self.args.values_mut() {
            (*arg).parse_from_hash(&arg_hash, &multi_vec)?;
        }

        Ok(ArgMatches::new(self.args))
    }

    fn output_help(&self) {
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
                HelpType::FLAGS => {
                    output_flags.push(help_str);
                }
                HelpType::OPTION => {
                    output_options.push(help_str);
                }
                HelpType::HIDDEN => {}
            }
        }

        // start output using stdout now
        let stdout = std::io::stdout();
        let mut handle = std::io::BufWriter::new(stdout);

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
        let mut arg = Arg::default();
        arg.name = name;
        arg
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
        let long_name = self.long.unwrap().to_string();

        if arg_hash.contains_key(&long_name) {
            if !self.multiple && multi_vec.contains(&long_name) {
                return Err(ErrorKind::DuplicateArgument(long_name).into());
            }

            if self.value.is_some() && (arg_hash[&long_name].len() > 1) && !self.multiple {
                return Err(ErrorKind::DuplicateValue(long_name).into());
            }

            if (self.value.is_some() || self.values.is_some()) && (arg_hash[&long_name].is_empty())
            {
                if self.can_no_value {
                    self.value = Some(Default::default());
                    self.presented = true;
                    return Ok(());
                } else {
                    return Err(ErrorKind::MissingValue(long_name).into());
                }
            }

            if (self.value.is_none() && self.values.is_none()) && (!arg_hash[&long_name].is_empty())
            {
                return Err(ErrorKind::IllegelValue(
                    arg_hash[&long_name][0].to_string(),
                    long_name.to_string(),
                )
                .into());
            }

            if self.value.is_some() {
                if self.possible_value_check(&arg_hash[&long_name][0]) {
                    self.value = Some(arg_hash[&long_name][0].clone());
                } else {
                    return Err(ErrorKind::ValueOutOfPossible(
                        long_name,
                        format!("{:?}", self.possible_values),
                    )
                    .into());
                }
            } else if self.values.is_some() {
                if self.possible_values_check(arg_hash[&long_name].clone()) {
                    self.values = Some(arg_hash[&long_name].clone());
                } else {
                    return Err(ErrorKind::ValueOutOfPossible(
                        long_name,
                        format!("{:?}", self.possible_values),
                    )
                    .into());
                }
            }

            self.presented = true;
        } else if self.required {
            return Err(ErrorKind::MissingArgument(long_name).into());
        }

        if self.short.is_some() {
            let short_name = self.short.unwrap();
            if arg_hash.contains_key(short_name) {
                if (self.value.is_none() && self.values.is_none())
                    && (!arg_hash[short_name].is_empty())
                {
                    return Err(ErrorKind::IllegelValue(
                        arg_hash[short_name][0].to_string(),
                        short_name.to_string(),
                    )
                    .into());
                }

                self.presented = true;
            } else if self.required {
                return Err(ErrorKind::MissingArgument(short_name.to_string()).into());
            }
        }

        Ok(())
    }

    /// Produce help message for argument.
    fn help_message(&self) -> (String, HelpType) {
        if self.hiddable {
            (String::new(), HelpType::HIDDEN)
        } else if self.short.is_some() {
            let font_str = format!(
                "{}{}{}, {}{}",
                FOUR_BLANK,
                PREFIX_CHARS_SHORT,
                self.short.unwrap(),
                PREFIX_CHARS_LONG,
                self.long.unwrap_or("")
            );
            let mut help_str = format!("{}{}", TWENTY_FOUT_BLANK, self.help.unwrap_or(""));
            let font_offset = font_str.len();
            help_str.replace_range(..font_offset, &font_str);
            (help_str, HelpType::FLAGS)
        } else {
            let font_str = if self.values.is_some() {
                format!(
                    "{}{}{} <{}>...",
                    EIGHT_BLANK,
                    PREFIX_CHARS_LONG,
                    self.long.unwrap(),
                    self.value_name.unwrap_or(self.name)
                )
            } else {
                format!(
                    "{}{}{} <{}>",
                    EIGHT_BLANK,
                    PREFIX_CHARS_LONG,
                    self.long.unwrap(),
                    self.value_name.unwrap_or(self.name)
                )
            };
            let mut help_str = format!(
                "{}{}{}{}",
                TWENTY_FOUT_BLANK,
                TWENTY_FOUT_BLANK,
                TWENTY_FOUT_BLANK,
                self.help.unwrap_or("")
            );
            let font_offset = font_str.len();
            help_str.replace_range(..font_offset, &font_str);
            (help_str, HelpType::OPTION)
        }
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
    fn new(args: BTreeMap<&'a str, Arg<'a>>) -> Self {
        let mut arg_matches = ArgMatches::default();
        arg_matches.args = args;
        arg_matches
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
}

#[allow(clippy::map_entry)]
fn parse_cmdline(allow_list: &[String]) -> Result<(ArgsMap, Vec<String>)> {
    let cmd_args: Vec<String> = env::args().collect();
    let mut arg_map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut multi_vec: Vec<String> = Vec::new();

    let mut i = (0, "");
    let mut j = 1;
    for cmd_arg in &cmd_args[1..] {
        if !allow_list.contains(&cmd_arg) && cmd_arg.starts_with(PREFIX_CHARS_SHORT) {
            return Err(ErrorKind::UnexpectedArguments(cmd_arg.to_string()).into());
        }

        if cmd_arg.starts_with(PREFIX_CHARS_LONG) {
            let arg_str = split_arg(cmd_arg, PREFIX_CHARS_LONG);
            if arg_map.contains_key(&arg_str) {
                multi_vec.push(arg_str);
            } else {
                arg_map.insert(arg_str, Vec::new());
            }

            i = (j, PREFIX_CHARS_LONG);
        } else if cmd_arg.starts_with(PREFIX_CHARS_SHORT) {
            let arg_str = split_arg(cmd_arg, PREFIX_CHARS_SHORT);
            if arg_map.contains_key(&arg_str) {
                multi_vec.push(arg_str);
            } else {
                arg_map.insert(arg_str, Vec::new());
            }
            i = (j, PREFIX_CHARS_SHORT);
        } else {
            let arg_str = match i.1 {
                PREFIX_CHARS_LONG => split_arg(&cmd_args[i.0], PREFIX_CHARS_LONG),
                &_ => {
                    return Err(ErrorKind::UnexpectedArguments(cmd_arg.to_string()).into());
                }
            };
            arg_map
                .get_mut(arg_str.as_str())
                .unwrap()
                .push(cmd_arg.to_string());
        }
        j += 1;
    }
    Ok((arg_map, multi_vec))
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
