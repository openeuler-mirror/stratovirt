// Copyright (c) 2024 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::{
    fs::File,
    io::{self, stdin, stdout, IoSliceMut},
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::net::{UnixListener, UnixStream},
    },
    process::exit,
    thread,
};

use anyhow::{anyhow, bail, Context, Result};
use clap::{builder::NonEmptyStringValueParser, crate_description, Parser};
use nix::{
    cmsg_space,
    errno::errno,
    sys::{
        socket::{recvmsg, ControlMessageOwned, MsgFlags, UnixAddr},
        termios::{tcgetattr, tcsetattr, OutputFlags, SetArg},
    },
};

#[derive(Parser, Debug)]
#[command(version, author, about = crate_description!())]
struct Cli {
    #[arg(short, long)]
    pub no_stdin: bool,
    // Specify path of console socket to connect.
    #[arg(value_parser = NonEmptyStringValueParser::new(), required = true)]
    pub console_socket: String,
}

fn clear_onlcr(fd: RawFd) -> Result<()> {
    let mut termios =
        tcgetattr(fd).with_context(|| anyhow!("tcgetattr error: errno {}, fd: {}", errno(), fd))?;
    termios.output_flags &= !OutputFlags::ONLCR;
    tcsetattr(fd, SetArg::TCSANOW, &termios)
        .with_context(|| anyhow!("tcsetattr error: errno {}", errno()))?;
    Ok(())
}

fn handle_connection(stream: &UnixStream, no_stdin: bool) -> Result<()> {
    let mut msg_iov = Vec::with_capacity(10);
    let mut iov = [IoSliceMut::new(msg_iov.as_mut_slice())];
    let mut cmsg_buffer = cmsg_space!([RawFd; 1]);
    let mut master: RawFd = -1;

    let ret = recvmsg::<UnixAddr>(
        stream.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_buffer),
        MsgFlags::empty(),
    )
    .with_context(|| "recvmsg error")?;
    for ctl_msg in ret.cmsgs() {
        match ctl_msg {
            ControlMessageOwned::ScmRights(fds) => master = fds[0],
            _ => (),
        }
    }

    clear_onlcr(master)?;
    let output = thread::spawn(move || {
        let mut us = unsafe { File::from_raw_fd(master) };
        io::copy(&mut us, &mut stdout())
    });
    if !no_stdin {
        let input = thread::spawn(move || {
            let mut us = unsafe { File::from_raw_fd(master) };
            io::copy(&mut stdin(), &mut us)
        });
        if let Err(e) = input.join().expect("Input thread has exited.") {
            eprintln!("Input thread error: {}", e);
        }
    }
    if let Err(e) = output.join().expect("Output thread has exited.") {
        eprintln!("Output thread error: {}", e);
    }

    Ok(())
}

fn listen_on_socket(listener: &UnixListener, no_stdin: bool) -> Result<()> {
    for stream in listener.incoming() {
        match stream {
            Ok(s) => handle_connection(&s, no_stdin)?,
            Err(e) => bail!("Failed to accept incoming connection: {}", e),
        }
    }
    Ok(())
}

fn real_main() -> Result<()> {
    let cli = Cli::parse();

    let listener =
        UnixListener::bind(&cli.console_socket).with_context(|| "Failed to bind to the socket")?;
    listen_on_socket(&listener, cli.no_stdin)?;

    Ok(())
}

fn main() {
    match real_main() {
        Ok(_) => exit(0),
        Err(e) => {
            eprintln!("{}", e);
            exit(1)
        }
    }
}
