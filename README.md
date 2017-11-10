# shadowsocks-OR

基于OpenResty的shadowsocks实现

### 说明

- 只支持服务端
- 支持有限的加密算法
- 不支持UDP转发
- 不支持OTA
- 不支持fast open
- 不支持IPv6

### 启动

```shell
nginx -p `pwd` -c nginx.conf
```

### 配置

- nginx.conf
    > 可以修改nginx监听端口
- config.lua
    > 修改shadowsocks密码
    > 修改加密算法, 查看shadowssocks/openssl.lua, 了解支持的加密算法

### 依赖

> <https://github.com/openresty/stream-lua-nginx-module>  
> <https://github.com/openresty/stream-lua-nginx-module/pull/33>

提供一个修改过了OpenResty版本

> <http://picbang.qiniudn.com/openresty-1.13.6.1rc1-bsd.tar.gz>

### 已知问题

openresty-1.13.6.1rc1-bsd.tar.gz

会导致Nginx Core Dump, 等待OpenResty稳定版本