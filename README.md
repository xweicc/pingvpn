# 把数据包装成Ping包的VPN
### 使用示例
- 系统环境：Ubuntu 22.04
- 编译：执行 `make`，生成内核模块pingvpn.ko和可执行文件pvpn
- 安装模块：`insmod pingvpn.ko`
- 服务端执行：
    - `./pvpn conf server`
    - `ifconfig pvpn 10.10.1.1 up`
- 客户端执行：
    - `./pvpn conf client serverIP alive(0/1)`
    - `ifconfig pvpn 10.10.1.2 up`
- 然后在客户端 `ping 10.10.1.1`，如果通了则VPN隧道建立成功
- 然后再根据需要建立路由表或NAT表即可
### 技术原理
- 发包流程
    - 模块创建了虚拟网卡，内核数据包通过查找路由表调用此网卡的发包函数`pingvpn_dev_xmit`
    - `pingvpn_dev_xmit`函数中，会做一些判断，只处理IPv4报文，如果是TCP syn报文，会修改MSS
    - 如果是服务端，还会根据五元组查找连接，用于判断数据有效和对应客户端
    - 然后调用`pingvpn_icmp_send`，此函数中，会将数据包封装成ICMP报文，再调用`pingvpn_skb_send`
    - `pingvpn_skb_send`函数中，会查找路由表选择出口，创建连接跟踪
- 收包流程
    - 通过netfilter钩子函数拦截ICMP协议的数据包，调用函数`pingvpn_dev_recv`
    - `pingvpn_dev_recv`函数中，会去掉ICMP头，重新设置连接跟踪，再调用`netif_rx`重新发送到内核协议栈
    - 如果是服务端，还会根据五元组创建连接，用于记录客户端的连接信息