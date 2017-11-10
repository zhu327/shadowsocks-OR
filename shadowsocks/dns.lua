local resolver = require "resty.dns.resolver"
local lrucache = require "resty.lrucache"


local LRU_TIME_OUT = 300 -- 300 seconds

local cache, err = lrucache.new(50)
if not cache then
    return error("failed to create the cache: " .. (err or "unknown"))
end


local _M = { _VERSION = '0.10' }


function _M:new(server_list)
    local o = {}

    local r, err = resolver:new{
        nameservers = server_list or {"8.8.8.8", "8.8.4.4"}
    }
    o._resolver = r

    setmetatable(o, { __index = self })

    return o
end

function _M:query(domain)
    local answers, err = self._resolver:query(domain)
    if not answers then
        ngx.log(ngx.INFO, "failed to query the DNS server: ", err)
        return nil
    end
    if answers.errcode then
        ngx.log(ngx.INFO, "server returned error code: ", answers.errcode,
            ": ", answers.errstr)
        return nil
    end
    local ans = answers[#answers]
    if ans.type == 1 then
        return ans.address
    end
end

function _M:resolve(domain)
    local ip = cache:get(domain)
    if not ip then
        ip = self:query(domain)
        if ip then
            cache:set(domain, ip, LRU_TIME_OUT)
        end
    end
    ngx.log(ngx.DEBUG, "dns resolve :", domain, " ", ip)
    return ip
end


return _M