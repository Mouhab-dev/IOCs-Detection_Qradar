# Qradar: IOCs Detection ![Python](https://img.shields.io/badge/-Python-black?style=flat&logo=Python) ![version](https://img.shields.io/badge/version-v1.0-blueviolet) ![platform](https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-green)

Qradar: IOCs Detection Script is a python script to help you search for IOCs in your environment through Qradar's logs using its API.

## Table of contents
* [General info](#general-info)
* [Libraries](#libraries)
* [Setup](#setup)
* [Usage](#usage)
* [Test](#test)

## General info
Qradar: IOCs Detection Script is a python script to help you search for IOCs in your environment through Qradar's logs using its API.

The Script can deal with the following types of IOCs:
* MD5
* SHA1
* SHA256
* URL
* Domain
* IP Address
* Email Sender
* Sender Domain

## Libraries
Project is created with:
* base64.
* json.
* requests.
* getpass.
* csv.
* re.
* pandas.
* python 3.6 or higher.

## Setup
To run this project, install all the required libraries first then confiure the python script as follows:

* Update the **host** variable with your Qradar's IP Address.
* Configure the **search_period** variable to your liking, please follow qradar's documentation in order not to break the search query.
* Then, Run the script using the following command:
```
$ python qradar_iocs.py
```

## Usage
Run the following command to display help message
```
hashy.py -h
```
or
```
hashy.py --help
```
A help message will appear with all required arguments the program needs to run:
```
usage: hashy.py [-h] [-v] -hf MD5:SHA1:blake2b [MD5:SHA1:blake2b ...]
                (-cf <file path> <file path> | -f <file path> | -s "String")

Hashy is a CLI program to hash files, compare two files (integrity check),
strings.

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         display current version of Hashy
  -hf MD5:SHA1:blake2b [MD5:SHA1:blake2b ...]
                        the required hash function.
  -cf <file path> <file path>
                        check hash of two files for a match using the provided
                        hash function.
  -f <file path>        calculate hash for a file using the provided hash
                        function.
  -s "String"           calculate hash for a string using the provided hash
                        function (string inside " " is recommended).

Find me on Github: https://www.github.com/Mouhab-dev
```
* -hf is essential for the script to run
* -cf / -f / -s :
only one of the previous arguments followed by the appropriate input is required to run the script.

## Test

Tested with a string being hashed with md5,sha1 and sha256 algorithms:

```
C:\Users\<current user>\Desktop> python hashy.py -hf md5 sha1 sha256 -s "hello world it's hashy here" 
Hashing string ...

Algorithm:         Hash value:
------------       --------------------------------------
md5                ba672a8326b0d3333c7296e73e0ec0ed
sha1               2e561e67dfe68f64d63204c7e96f0dccaec5cb00
sha256             eb43f53ec1b2d25c0361574e99b4257a5a84d123f7e265e0434e03789276d460

Process Finished
```


