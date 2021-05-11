# cayenne
## 内核
LINUX 4.15.0-143-generic  
## DEMO
```
GET / HTTP/1.1
Host: 192.168.122.136
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
cookie: sysaya
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 Edg/90.0.818.51
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Connection: close
```
## FAQ
如遇错误
```
cayenne: Unknown symbol __nf_nat_mangle_tcp_packet (err -2)
```
先执行如下语句后再重试insmod  
```
sudo iptables -t nat --list
```