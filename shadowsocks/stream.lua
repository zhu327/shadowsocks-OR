local cryptor = require "cryptor"
local common = require "common"
local dns = require "dns"


local STAGE_ADDR = 0
local STAGE_STREAM = 1
local STAGE_DESTROYED = -1

local TIMEOUT = config["timeout"] * 1000


local _M = { _VERSION = '0.10' }


function _M:new(sock)

    sock:settimeout(TIMEOUT)

    local o = {}
    o._closed = false
    o._stage = STAGE_ADDR
    o._local_sock = sock
    o._cryptor = cryptor:new(config["password"], config["method"])
    if not o._cryptor then
        return nil
    end

    setmetatable(o, { __index = self })

    return o
end

function _M:local_loop()
    while not self._closed do
        local data, err, partial = self._local_sock:receive("*b")
        if not data then
            self._closed = true
            ngx.log(ngx.DEBUG, "local sock read error :", (err or ""))
            return
        end
        data = self._cryptor:decrypt(data)
        if data then
            if self._stage == STAGE_ADDR then
                self:connect_remote(data) -- create remote sock
                if self._closed then
                    return
                end
                -- start remote loop
                self._thread = ngx.thread.spawn(self.remote_loop, self)
            else
                local bytes, err = self._remote_sock:send(data)
                if not bytes then
                    self._closed = true
                    ngx.log(ngx.DEBUG, "remote sock write error :", (err or ""))
                    return
                end
            end
        else
            ngx.log(ngx.DEBUG, "local data decrypt error :", data)
        end
    end
end

function _M:connect_remote(data)
    local addrtype, remote_addr, remote_port, header_length = common.parse_header(data)
    if (addrtype == common.AddressType.DomainName) and remote_addr then
        local resolver = dns:new(config["dns_server"])
        remote_addr = resolver:resolve(remote_addr)
    end
    if not remote_addr then
        self._closed = true
        ngx.log(ngx.DEBUG, "get remote_addr error :", data)
        return
    end
    local sock = ngx.socket.tcp()
    sock:settimeout(TIMEOUT)
    local ok, err = sock:connect(remote_addr, remote_port)
    if not ok then
        self._closed = true
        ngx.log(ngx.DEBUG, "remote sock connect error :", (err or ""))
        return
    end
    self._remote_sock = sock
    if #data > header_length then
        local playload = data:sub(header_length+1)
        local bytes, err = sock:send(playload)
        if not bytes then
            self._closed = true
            ngx.log(ngx.DEBUG, "first remote sock write error :", (err or ""))
            return
        end
    end
    self._stage = STAGE_STREAM
end

function _M:remote_loop()
    while not self._closed do
        local data, err, partial = self._remote_sock:receive("*b")
        if not data then
            self._closed = true
            ngx.log(ngx.DEBUG, "remote sock read error :", err)
            if partial then
                data = partial
            else
                return
            end
        end
        data = self._cryptor:encrypt(data)
        local bytes, err = self._local_sock:send(data)
        if not bytes then
            self._closed = true
            ngx.log(ngx.DEBUG, "local sock write error :", (err or ""))
            return
        end
    end
end

function _M:wait()
    if self._thread then
        ngx.thread.wait(self._thread)
    end
end

function _M:destroy()
    if self._stage == STAGE_DESTROYED then
        return
    end
    if self._local_sock then
        local ok, err = self._local_sock:shutdown("send")
        if not ok then
            ngx.log(ngx.DEBUG, "local sock close error :", (err or ""))
        end
        self._local_sock = nil
    end
    if self._remote_sock then
        local ok, err = self._remote_sock:close()
        if not ok then
            ngx.log(ngx.DEBUG, "remote sock close error :", (err or ""))
        end
        self._remote_sock = nil
    end
    self._cryptor = nil
    self._thread = nil
    self._stage = STAGE_DESTROYED
end


return _M