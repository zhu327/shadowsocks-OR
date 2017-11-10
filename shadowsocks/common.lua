local _M = { _VERSION = '0.10' }

local AddressType = {
    IPv4 = 0x01,
    DomainName = 0x03,
    IPv6 = 0x04,
}

local function parse_header(data)
    local dest_addr, dest_port, header_length
    local addrtype = data:byte(1)
    if addrtype == AddressType.IPv4 then
        if #data >= 7 then
            local ipBytes = {data:byte(2, 5)}
            dest_addr = table.concat(ipBytes, '.')
            local portBytes = {data:byte(6, 7)}
            dest_port = portBytes[1] * 256 + portBytes[2]
            header_length = 7
        end
    elseif addrtype == AddressType.DomainName then
        if #data > 2 then
            local addrlen = data:byte(2)
            if #data >= 4 + addrlen then
                dest_addr = data:sub(3, 3 + addrlen - 1)
                local portBytes = {data:byte(3 + addrlen, 4 + addrlen)}
                dest_port = portBytes[1] * 256 + portBytes[2]
                header_length = 4 + addrlen
            end
        end
    end
    ngx.log(ngx.DEBUG, "parse header :", dest_addr, " ", dest_port)
    return addrtype, dest_addr, dest_port, header_length
end

_M.AddressType = AddressType
_M.parse_header = parse_header


return _M