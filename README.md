# RouterOSv7 For Aliyun DDNS
支持阿里云域名动态解析的 RouterOS V7 脚本及对应的转发代理。
说明：
- 需要 RouterOS 脚本搭配一个转发代理程序使用。转发代理使用阿里云的 V3 版签名方案，只有一个 PHP 文件，不需要安装 SDK，可部署到各种 PHP 网站空间。
- 只支持 RouterOS V7 以上版本。转发代理功能经过简化，只支持域名查询和修改两个功能。
- RouterOS 的开头部分为用户变量，需要自行修改，详见注释。
- 域名的 DNS 服务器要指向阿里云。需要在阿里云上自行配置一个支持 DNS 解析权限的 AccessKey。
- 为防止转发代理被滥用，使用了安全令牌（securityToken）和白名单，安全令牌需要 RouterOS 脚本和 PHP 代码中保持一致，白名单在 PHP 代码中添加。详见代码中的注释。
- RouterOS 脚本中增加了一个通过钉钉机器人发送消息通知功能，若不需要可自行屏蔽。
- RouterOS 脚本目前的设置是 IPV4，如要支持 IPV6，需要将 recordType 的值由 A 改为 AAAA，同时修改获取公网 IP 的方式：如从支持 IPV6 的路由器接口获取 IP，或者由 https://6.ipw.cn 之类的网站返回 IP。
- 转发代理目前只有一个 PHP 版本，以后可能会增加其它语言版本。
- RouterOS 脚本建议由 PPPOE 拨号 的 Profiles 配置中的 On Up 脚本中调用。最好是先用 delay 3s 命令延时几秒。
- RouterDDNS.txt 为 RouterOS 脚本文件。
- aliyun-ddns.php 为 PHP 转发代理。
