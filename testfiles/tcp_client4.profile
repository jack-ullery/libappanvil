/tmp/tcp/tcp_client {
tcp_connect to 10.0.0.17/16:50-100 from 0.0.0.0:50-100 via eth1 ,
tcp_connect to 127.0.0.1	,
tcp_connect from 12.13.14.15/31:21,
tcp_accept from 12.13.15.128/25:1024-2048 via eth2,
tcp_accept from 10.0.1.1/24:1024-2048 to 192.168.1.1:70 via eth2:1,
tcp_accept to 192.168.2.1:70 from 10.0.2.1/24:1024-2048 via eth2:2,
tcp_connect to 192.168.3.1:70 from 10.0.3.1/24:1024-2048 via eth2:3,
tcp_connect from 10.0.4.1/24:1024-2048 to 192.168.4.1:70 via eth2:4,
# syntactic suger cdub asked for:
udp_send via eth0,
udp_receive via eth1,
# attempt an ip style netmask
tcp_connect from 10.0.4.1/255.0.255.0:1024-2048 to 192.168.4.1:70 via eth2:4,
/lib/libc.so.6		r	,
/lib/ld-linux.so.2	r	,
/etc/ld.so.cache	r	,
/lib/libc-2.1.3.so	r	,
}
