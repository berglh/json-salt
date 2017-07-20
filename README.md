
# json-salt
[![Build Status](https://travis-ci.org/berglh/json-salt.svg?branch=master)](https://travis-ci.org/berglh/json-salt)<br />

**json-salt** is a command-line tool written in *Go* that reads in arbitrary *valid* JSON from a file and given a particular key string will *salt* and *hash* it in a standard manner.

The goal is to obfuscation/pseudo-anonymisation|anonymization with a consistent method. This tool was built in the light of hashing identifying information to profile users across disparate data sources for further group analysis.

- [Information](#information)
  - [Limitations](#limitations)
- [Usage](#usage)
  - [Arguments](#arguments)
  - [Switches](#switches)
- [Limitations](#limitations)
- [Examples](#examples)


## Information

Currently, `json-salt` outputs by default in JSON line format because it's typically easier to handle than pretty printed JSON.

The hashing method implemented is `md5`.  The salting method implemented is *basic* and prepends the salt like so:

```
yoursaltkeyvalue

```

#### Limitations & Possible Bugs

* Only hashes one key per run, usually one field is enough to identify a user across multiple disparate datasets
* Only one method for salting currently by pre-pending the salt, custom pattern flag could be implemented
* Only md5sum hashing has been implemented, other hashing methods could be implemented
* Has not been tested with referencing keys, objects or JSON documents inside arrays
* Has not been tested with first level fields that require hashing

Let me know what doesn't work for you in the issues page.


## Usage

Currently **json-salt** outputs the hashed JSON to stdout and prints program information to stderr. If it has troubles decoding JSON it will probably freak out.

#### Arguments
Flag | Example | Description
:---:|:----|:---
`-f` | `/path/to/file.json` | Specify the path to the JSON file to salt and hash.
`-k` | `outer.inner.third.key` | The path to the key name to hash, separated by delimiter for nested keys`.
`-s` | `astringofsalt` | Salt to hash the value with.
`-d` | `.` | Specify custom delimiter for nested key path in case you have dots in your field names, dot delimiter by default.


#### Switches
Flag | Description
:---:|:----
`-h`| Displays the usage information.
`-lc`| Convert key value to lower-case before hashing.
`-uc`| Convert key value to upper-case before hashing.
`-w`| Strip trailing and leading white-space on key value before hashing.
`-pretty`| Pretty print the JSON output instead of JSON lines.k
`-version`| Print the program version.


## Examples

Run **json-salt** without the salt flag and it will prompt you to enter it without echoing the salt to the terminal:

```
~$ json-salt -k source.user.uid -w -lc -f ~/path/to/file.json > outputfile.json
Enter salt to hash with: 

```

Run **json-salt** with the salt flag to batch hash a series of JSON files:

```
~$ for file in *.json; do json-salt -k source.user.uid -f $file -s yoursalt > ${file/.json/-hashed.json}
```