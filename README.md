# Auto-NMAP Script Scanning Tool Using Python NMAP Library #

# About #
It will execute port scanning & identify service, then using **NMAP brute NSE script** & **other brute-force tools** (ex:HYDRA) focus on open ports and services, then find possible **USERNAME** & **PASSWORD**. 
 
This tool include 2 of python files & 2 of directories:
   1. *main.py*
   2. *NSE_Moudle.py*
   3. *[dict]*
   4. *[thc-hydra-windows-master]*
   
### main.py ###
Main program. it included user arguments input, brute-force function call and print results (on command windows)

### NSE_Moudle.py ###
Brute-force function module. it included NSE script scan function & HYDRA function.

BTW, if tool execute in Windows OS, there are settings in line 17~26:
```python
strHYDRA_Path = os.path.dirname(__file__) + '\\thc-hydra-windows-master\hydra.exe'
strUserName_Path = '/dict/usernames.lst'
strPassword_Path = '/dict/passwords.lst'
```

Otherwise, if tool execute in Linux KALI OS, there are settings in line 28~38:
```python
strHYDRA_Path = '/usr/bin/hydra'
strUserName_Path = './dict/usernames.lst'
strPassword_Path = './dict/passwords.lst'
```
### [dict] ###
Dictionary files directory

### [thc-hydra-windows-master] ###
HYDRA tool directory. if tool excute in Windows OS, it will need this tool. But, if tool execute in LINUX KALI OS, it won't need this tool. (HYDRA already installed in KALI OS)

## Usage ##
Type in command line:
* python main.py HOST_IP [-h] [-o HYDRA]
* [EXAMPLE 1]: *python main.py 127.0.0.1*
* [EXAMPLE 2]: *python main.py 127.0.0.1 -o HYDRA*

  **positional arguments:**
  *  HOST_IP:  Target HOST IP Address

  **optional arguments:**
  *  -h, --help: Show this help message and exit
  *  -o OPT: Using other tools brute-force, OPT is tool's name. Support tool lists: HYDRA

---
  
# python-nmap library #
python-nmap is a python library which helps in using nmap port scanner. About download, installation & usage, please visit original author site.
(Ref URL: https://xael.org/pages/python-nmap-en.html)

## Install from PIP ##

Installing python-nmap is just as simple as :
*pip install python-nmap*

## Manual installation ##

From the shell, uncompress python-nmap-0.4.0.tar.gz and then run make:

*tar xvzf python-nmap-0.6.1.tar.gz
cd python-nmap-0.6.1
python setup.py install*

## Usage ##

In python-nmap library, it supports three kinds of input.
1. *Only IP address*: Port scanning on well-known with service version check
   python code sample: **nm.scan('127.0.0.1')**
   nmap command: **nmap -oX - -sV 127.0.0.1**

2. *IP address with port number (or port range)*: Port scanning on specified ports
   python code sample: **nm.scan('127.0.0.1', '22-443')**
   nmap command: **nmap -oX - -p 22-443 -sV 127.0.0.1**

3. *IP address with arguments*: Port scanning with arguments action.
   python code sample: **nm.scan('127.0.0.1', arguments='-p 21 -script=ftp-brute')**
   nmap command: **nmap -oX - -p 21 -script=ftp-brute -sV 127.0.0.1**
 
---
  
# Auto-NMAP Script Scanning Tool #

## Concept ##
When executing **main.py**:
1. Well-known port scanning on target hosts, list open ports on every target hosts
2. Parsing port scanning result and extracting 4 values about:
* <product>: application product name
* <version>: appplication version number
* <name>: application service name
* <ports>: application open port
   
   Identifing by service name, if same service on different ports, then its will be conclude into same record and using ';' or ',' to delimit
   * <products>: using ';' to delimit 
   * <veriosns>: using ';' to delimit 
   * <ports>: using ',' to delimit
3. Storing extracted informations & values in *Dictionary Variable<dictPortScan>*. Format is:
```XML
'192.168.107.129': {
  'ftp': {
    'product': 'vsftpd;ProFTPD',
    'version': '2.3.4;1.3.1',
    'port': '21,2121'
  }
}
```
4. Every open service will execute NSE brute script scanning(or HYDRA). 
5. Scanning result will store back into <dictPortScan> variable. 
   Result include port number, script name & scanning result.
```XML
  '192.168.107.129': {
    'ftp': {
      'product': 'vsftpd;ProFTPD',
      'version': '2.3.4;1.3.1',
      'port': '21,2121',
      'script': {
        21: { <!--NMAP NSE Script scanning result-->
          'ftp-brute': '\n  Accounts: \n    user:user - Valid credentials\n  Statistics: Performed 3635 guesses in 602 seconds, average tps: 6.0'
        },
        22: [{ <!-- HYDRA scanning result-->
            'username': 'user', 'password': 'user'
        }]
      }
    },
```
## Function ##
* Looking for well-known service name, and call brute function
* Function parameters are *1.) IP, 2.)Ports and 3.) Original scanning result*.
* Using *IP & Ports* to create scanning arguments and execute scanning.
* After executing script scan, parse script scanning result stored back into *Original scanning result*.

Example code: 

```python
# in main.py
if 'ftp' in dictPortScan[ip].keys():
  if args.opt == 'HYDRA': 
    nseScript.HYDRA(ip, dictPortScan[ip]['ftp']['ports'], 'ftp', dictPortScan[ip]['ftp'])
  else: 
    nseScript.FTP(ip, dictPortScan[ip]['ftp']['ports'], dictPortScan[ip]['ftp'])

# in NSE_Module.py
def FTP(self, ip, ports, host):
  # NMAP variable in FTP func()
  nmScan_FTP = nmap.PortScanner()
  # Dictionary variable for script results (temporary)
  dictScript = {}
  # concat port & other nmap command flag
  strArgs = '-p ' + ports + ' -script=ftp-brute'
  # FTP brute force script scaning
  nmScan_FTP.scan(ip, arguments=strArgs)
  # List Script Name & Scanning result
  for port in nmScan_FTP[ip]['tcp']:
    thisDict = nmScan_FTP[ip]['tcp'][port]
    if 'script' in thisDict: 
      dictScript[str(port)] = {} #initail dictScript{}
      for thisScript in thisDict['script']:
        dictScript[str(port)][str(thisScript)] = thisDict['script'][str(thisScript)]
    else:
      # No result
  host['scripts'] = dictScript # store back
    
  return 0
```
## Support Service ##


| Service Name        | NSE Script | HYDRA           |
| ------------------- | ---------- | --------------- |
| FTP                 | Supported  | Supported       |
| SSH                 | Supported  | Supported       |
| Telnet              | Supported  | Supported       |
| SMTP                | Supported  | Supported       |
| DNS                 | Supported  | Not Supported   |
| HTTP                | Supported  | To be Supported |
| POP3                | Supported  | Supported       |
| SMB                 | Supported  | Supported       |
| SNMP                | Supported  | Supported       |
| IMAP                | Supported  | Supported       |
| LDAP                | Supported  | To be Supported |
| HTTPS               | Supported  | To be Supported |
| EXEC                | Supported  | Supported       |
| LOGIN               | Supported  | Supported       |
| Microsoft SQL Server| Supported  | Supported       |
| Oracle              | Supported  | Supported       |
| MySQL               | Supported  | Supported       |
| PostgreSQL          | Supported  | Supported       |
| VNC                 | Supported  | Supported       |
| ApacheJServProtocol | Supported  | Not Supported   |
| MongoDB             | Supported  | Not Supported   |
| IBM DB2             | Supported  | Not Supported   |
