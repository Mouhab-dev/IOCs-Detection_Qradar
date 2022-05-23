# Qradar: IOCs Detection ![Python](https://img.shields.io/badge/-Python-black?style=flat&logo=Python) ![version](https://img.shields.io/badge/version-v1.0-blueviolet) ![platform](https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-green)

Qradar: IOCs Detection Script is a python script to help you search for IOCs in your environment through Qradar's logs using its API.

## Table of contents
* [General info](#general-info)
* [Libraries](#libraries)
* [Setup](#setup)
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
* Adjust **each search query** to your corresponding field name in your environment.
* Then, Run the script using the following command:

```
$ python qradar_iocs.py
```

## Test

Tested with a set of IOCs:

```
C:\Users\<current user>\Desktop> python qradar_iocs.py
Welcome to 
 __   __        __        __         __   __   __      __   ___ ___  ___  __  ___    __       
/  \ |__)  /\  |  \  /\  |__) .   | /  \ /  ` /__`    |  \ |__   |  |__  /  `  |  | /  \ |\ |
\__X |  \ /~~\ |__/ /~~\ |  \ .   | \__/ \__, .__/    |__/ |___  |  |___ \__,  |  | \__/ | \|
                                                                                 Version: 1.0
                                                                           By: Mohab El-Banna
                                                                           Github: Mouhab-dev
                                                                           
Password:
```



