local stream = require "stream"

local sock = assert(ngx.req.socket(true))

local tcpstream = stream:new(sock)
if not tcpstream then
    ngx.log(ngx.DEBUG, "instantiate stream faild")
    return
end

tcpstream:local_loop()
tcpstream:wait()
tcpstream:destroy()