#python3 shadowsocks/local.py -k password -s localhost -p 4567 -vv
python3 shadowsocks/local.py -k password -s 127.0.0.1 -p 4567 -b 127.0.0.1 -vv

#curl -x socks5h://127.0.0.1:1080 http://apitest.anyayi.com/test.gif --output -
#curl -x socks5h://127.0.0.1:1080 http://www.baidu.com
