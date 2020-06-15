Asshole
===========


A fast tunnel proxy that helps you bypass firewalls.

Features:
- Elliptic Curve Cryption for proxy traffic
- TCP & UDP support
- User management API
- TCP Fast Open
- Workers and graceful restart
- Destination IP blacklist


## Usage
Require python 3.7 or above installed.


You need two servers, one is inside the wall(local server), the other is outside the wall(remote server).

### 1. Installation
On both servers, download source code and install required package.
```
git clone https://github.com/yuan-xy/asshole.git
cd asshole
pip install -r requirements.txt
```


###2. Start Remote Server
```
python3 asshole/server.py -k your_pass -p your_port -d start -v
```
change `your_port` to real port, `your_pass` to your real password.


###3. Start Local Server
```
python3 asshole/local.py -k your_pass -s remote_server_ip -p remote_port -b 0.0.0.0 -v
```
change `remote_server_ip` and `remote_port` to your remote server ip and port.

The local server will start listen on port 1080 as a socks5 proxy.

###4. Make your system use this socks5 proxy.

You can test it with curl:
```
curl -x socks5h://127.0.0.1:1080 http://example.com
```

Browser plugins such as `SwitchyOmega` can be used with socks5 proxy. 


On windows, you can Forcing-Chrome-to-Use-Socks5-Proxy like this:
```
your_path_to_chrome\chrome.exe --proxy-server="socks5://127.0.0.1:1080" --host-resolver-rules="MAP * ~NOTFOUND, EXCLUDE 127.0.0.1"
```
