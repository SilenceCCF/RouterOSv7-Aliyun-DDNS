# RouterOSv7 For Aliyun DDNS
支持阿里云域名动态解析的 RouterOS V7 脚本及对应的转发代理。

说明：
- 需要 RouterOS 脚本搭配一个转发代理程序使用。转发代理使用阿里云的 V3 版签名方案，只有一个 PHP 文件，不需要安装 SDK，可部署到各种 PHP 网站空间。
- 只支持 RouterOS V7 以上版本。转发代理功能经过简化，只支持以 GET 方式进行域名查询和修改两个功能。
- RouterOS 的开头部分为用户变量，需要自行修改，详见注释。
- 域名的 DNS 服务器要指向阿里云。需要在阿里云上自行配置一个支持 DNS 解析权限的 AccessKey。
- 为防止转发代理被滥用，使用了安全令牌（securityToken）和白名单，安全令牌需要 RouterOS 脚本和 PHP 代码中保持一致，白名单在 PHP 代码中添加。详见代码中的注释。
- RouterOS 脚本中增加了一个通过钉钉机器人发送消息通知功能，若不需要可自行屏蔽。
- 路由器公网 IP 的获取由从 /ip/addresses 中查询改为从 PPPOE 拨号的 On Up 事件脚本中获取，好处是无须在 AliyunDDNS 脚本中指定接口名称。
- 脚本支持多条 PPPOE 拨号线路。
- 转发代理目前只有一个 PHP 版本，以后可能会增加其它语言版本。
- PHP 端有日志功能，并可自行关闭，详见代码中用户配置部分。日志中不会记录用户的 AccessKeySecret。
- AliyunDDNS.txt 为 RouterOS 进行动态域名操作的主脚本文件。
- PPP_Profile_OnUp.txt 的内容填写在 PPPOE 拨号接口使用的的 Profile 配置中的 On Up 脚本处，它的用途是将获取到的接口名称和公网 IP 地址传递给 AliyunDDNS 脚本。
- aliyun-ddns.php 为 PHP 转发代理。
