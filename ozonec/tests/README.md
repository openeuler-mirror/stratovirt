# Integration Tests

ozonec uses [bats (Bash Automated Testing System)](https://github.com/bats-core/bats-core) framework to run
integration tests written in *bash*.

## Before running tests

Install [bats (Bash Automated Testing System)](https://github.com/bats-core/bats-core#installing-bats-from-source) from source:
```
$ git clone https://github.com/bats-core/bats-core.git
$ cd bats-core
$ ./install.sh /usr/local
```

And *jq* is may also needed to modify json file in tests.

## Running tests

You can run tests using bats directly. For example:
```
bats ./
```
Or you can just run a single test file. For example:
```
bats create.bats
```

## Writing tests

Please refer to [bats (Writing tests)](https://bats-core.readthedocs.io/en/stable/writing-tests.html).