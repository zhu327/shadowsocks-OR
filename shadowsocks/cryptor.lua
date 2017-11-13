local resty_md5 = require "resty.md5"
local openssl = require "openssl"


local CIPHER_ENC_ENCRYPTION = 1
local CIPHER_ENC_DECRYPTION = 0

local METHOD_INFO_KEY_LEN = 1
local METHOD_INFO_IV_LEN = 2
local METHOD_INFO_CRYPTO = 3

local method_supported = openssl.ciphers
local cached_keys = {}


local _M = { _VERSION = '0.10' }
local mt = { __index = _M }


local function random_string(length)
    local buffer = {}
    for i = 1, length do buffer[i] = math.random(0, 255) end
    return string.char(unpack(buffer))
end

local function evp_bytestokey(password, key_len, iv_len)
    local cached_key = string.format("%s-%d-%d", password, key_len, iv_len)
    local r = cached_keys[cached_key]
    if r then
        return r[1], r[2]
    end

    local m, i = {}, 0
    while #(table.concat(m)) < (key_len + iv_len) do
        local md5 = resty_md5:new()
        local data = password
        if i > 0 then data = m[i] .. password end
        md5:update(data)
        m[#m + 1], i = md5:final(), i + 1
    end
    local ms = table.concat(m)
    local key = ms:sub(1, key_len)
    local iv = ms:sub(key_len + 1, iv_len)
    cached_keys[cached_key] = {key, iv}
    return key, iv
end

function _M.check_cipher_method(cipher_name)
    local method = string.lower(cipher_name)
    local method_info = method_supported[method]
    if method_info then
        return true
    else
        return false
    end
end

function _M:new(password, method)
    local o = {
        password = password,
        method = method,
        iv_sent = false
    }

    setmetatable(o, mt)

    o._method_info = self.get_method_info(method)
    if o._method_info then
        o.cipher = o:get_cipher(
                password, method, CIPHER_ENC_ENCRYPTION,
                random_string(o._method_info[METHOD_INFO_IV_LEN]))
        if not o.cipher then
            return nil
        end
    end
    return o
end

function _M.get_method_info(method)
    local method = string.lower(method)
    return method_supported[method]
end

function _M:get_cipher(password, method, op, iv)
    local key
    local m = self._method_info
    if m[METHOD_INFO_KEY_LEN] > 0 then
        key, _ = evp_bytestokey(password,
                                m[METHOD_INFO_KEY_LEN],
                                m[METHOD_INFO_IV_LEN])
    else
        key, iv = password, ''
    end
    iv = iv:sub(1, m[METHOD_INFO_IV_LEN])
    if op == CIPHER_ENC_ENCRYPTION then
        self.cipher_iv = iv
    end
    return m[METHOD_INFO_CRYPTO](method, key, iv, op)
end

function _M:encrypt(buf)
    if #buf == 0 then
        return buf
    end
    if self.iv_sent then
        return self.cipher:encrypt(buf)
    else
        self.iv_sent = true
        return self.cipher_iv .. self.cipher:encrypt(buf)
    end
end

function _M:decrypt(buf)
    if #buf == 0 then
        return buf
    end
    if self.decipher == nil then
        local decipher_iv_len = self._method_info[METHOD_INFO_IV_LEN]
        local decipher_iv = buf:sub(1, decipher_iv_len)
        self.decipher_iv = decipher_iv
        self.decipher = self:get_cipher(
            self.password, self.method,
            CIPHER_ENC_DECRYPTION,
            decipher_iv
        )
        buf = buf:sub(decipher_iv_len+1)
        if #buf == 0 then
            return buf
        end
    end
    return self.decipher:decrypt(buf)
end


return _M