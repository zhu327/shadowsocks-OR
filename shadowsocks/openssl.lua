local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_gc = ffi.gc
local ffi_str = ffi.string
local ffi_copy = ffi.copy
local C = ffi.C
local setmetatable = setmetatable


local _M = { _VERSION = '0.10' }
local mt = { __index = _M }


ffi.cdef[[
typedef struct engine_st ENGINE;
typedef struct evp_cipher_st EVP_CIPHER;

typedef struct evp_cipher_ctx_st
{
const EVP_CIPHER *cipher;
ENGINE *engine;
int encrypt;
int buf_len;

unsigned char  oiv[16];
unsigned char  iv[16];
unsigned char buf[32];
int num;

void *app_data;
int key_len;
unsigned long flags;
void *cipher_data;
int final_used;
int block_mask;
unsigned char final[32];
} EVP_CIPHER_CTX;

const EVP_CIPHER *EVP_get_cipherbyname(const char *name);
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);

int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
        ENGINE *impl, unsigned char *key, unsigned char *iv, int enc);
int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
         int *outl, unsigned char *in, int inl);

int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *a);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
]]

local buf_size = 2048
local buf = ffi_new("unsigned char[?]", buf_size)

local function c_uchar(s)
    local c_s = ffi_new("unsigned char[?]", #s)
    ffi_copy(c_s, s)
    return c_s
end

function cleanup(ctx)
    C.EVP_CIPHER_CTX_cleanup(ctx)
    C.EVP_CIPHER_CTX_free(ctx)
end

function _M:new(cipher_name, key, iv, op)
    local o = {
        ["_cipher"] = C.EVP_get_cipherbyname(cipher_name),
        ["_ctx"] = C.EVP_CIPHER_CTX_new()
    }

    if (not o._cipher) or (not o._ctx) then
        ngx.log(ngx.INFO, "openssl failed to create cipher or ctx ", cipher_name)
        return nil
    end

    setmetatable(o, mt)

    local r = C.EVP_CipherInit_ex(o._ctx, o._cipher, nil, c_uchar(key), c_uchar(iv), op)
    if r == 0 then
        ngx.log(ngx.INFO, "openssl failed to call EVP_CipherInit_ex ", cipher_name, " ", key, " ", iv)
        return nil
    end

    ffi_gc(o._ctx, cleanup)

    return o
end

function _M:update(data)
    local out_len = ffi_new("int[1]")
    local l = #data
    if buf_size < l then
        buf_size = l * 2
        buf = ffi_new("unsigned char[?]", buf_size)
    end
    if C.EVP_CipherUpdate(self._ctx, buf, out_len, c_uchar(data), l) == 0 then
        ngx.log(ngx.INFO, "openssl failed to call EVP_CipherUpdate")
        return nil
    end
    return ffi_str(buf, out_len[0])
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