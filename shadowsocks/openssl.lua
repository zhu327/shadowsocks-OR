local setmetatable = setmetatable

local cipher = require "resty.openssl.cipher"

local _M = { _VERSION = '0.10' }
local mt = { __index = _M }

function _M:new(cipher_name, key, iv, op)
    local o = {
        ["_cipher"] = assert(cipher.new(cipher_name))
    }
    setmetatable(o, mt)
    assert(o._cipher:init(key, iv, {["is_encrypt"] = op}))
    return o
end

function _M:update(data)
    return self._cipher:update(data)
end

function _M:encrypt(data)
    return self:update(data)
end

function _M:decrypt(data)
    return self:update(data)
end

local function create_cipher(alg, key, iv, op)
    return _M:new(alg, key, iv, op)
end

_M.ciphers = {
    ["aes-128-cfb"] = {16, 16, create_cipher},
    ["aes-192-cfb"] = {24, 16, create_cipher},
    ["aes-256-cfb"] = {32, 16, create_cipher},
    ["aes-128-ofb"] = {16, 16, create_cipher},
    ["aes-192-ofb"] = {24, 16, create_cipher},
    ["aes-256-ofb"] = {32, 16, create_cipher},
    ["aes-128-ctr"] = {16, 16, create_cipher},
    ["aes-192-ctr"] = {24, 16, create_cipher},
    ["aes-256-ctr"] = {32, 16, create_cipher},
    ["aes-128-cfb8"] = {16, 16, create_cipher},
    ["aes-192-cfb8"] = {24, 16, create_cipher},
    ["aes-256-cfb8"] = {32, 16, create_cipher},
    ["aes-128-cfb1"] = {16, 16, create_cipher},
    ["aes-192-cfb1"] = {24, 16, create_cipher},
    ["aes-256-cfb1"] = {32, 16, create_cipher},
    ["bf-cfb"] = {16, 8, create_cipher},
    ["camellia-128-cfb"] = {16, 16, create_cipher},
    ["camellia-192-cfb"] = {24, 16, create_cipher},
    ["camellia-256-cfb"] = {32, 16, create_cipher},
    ["cast5-cfb"] = {16, 8, create_cipher},
    ["des-cfb"] = {8, 8, create_cipher},
    ["idea-cfb"] = {16, 8, create_cipher},
    ["rc2-cfb"] = {16, 8, create_cipher},
    ["rc4"] = {16, 0, create_cipher},
    ["seed-cfb"] = {16, 16, create_cipher}
}

return _M