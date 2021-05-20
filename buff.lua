do
    local p_buff = Proto("buff", "buffge buff")
    local f_version = ProtoField.uint8("buff.version", "version", base.DEC)
    local f_opcode = ProtoField.uint8("buff.opcode", "opcode", base.DEC)
    local f_priority = ProtoField.uint8("buff.priority", "priority", base.HEX)
    local f_resv = ProtoField.uint8("buff.resv", "resv", base.HEX)
    local f_command = ProtoField.uint16("buff.command", "command", base.DEC)
    local f_length = ProtoField.uint16("buff.length", "length", base.DEC)
    local f_id = ProtoField.uint64("buff.id", "id", base.HEX)
    local f_expire = ProtoField.uint64("buff.expire", "expire", base.DEC)
    local f_data = ProtoField.string("buff.data", "data", base.UNICODE)
    p_buff.fields = {
        f_version, f_opcode, f_priority, f_resv, f_command,
        f_length, f_id, f_expire, f_data
    }
    local cmdMap = {
        [1] = "ping",
        [2] = "pong",
        [3] = "用户上线"
    }
    local data_dis = Dissector.get("data")
    local function buff_dissector(buf, pkt, root)
        local buf_len = buf:len();
        if buf_len < 24 then
            return false
        end
        local v_version = buf(0, 1)
        if (v_version:uint() ~= 0x01) then
            return false
        end
        local v_opcode = buf(1, 1)
        local v_priority = buf(2, 1)
        local v_resv = buf(3, 1)
        local v_command = buf(4, 2)
        local v_length = buf(6, 2)
        if (v_length:le_uint() ~= (buf_len - 24)) then
            return false
        end
        local v_id = buf(8, 8)
        local v_expire = buf(16, 8)
        local v_data = buf(24, buf_len - 24):string(ENC_UTF_8)
        local t = root:add(p_buff, buf)
        pkt.cols.protocol = "buff"
        pkt.cols.info:set(pkt.src_port .. " -> " .. pkt.dst_port)
        local cmd = cmdMap[v_command:le_uint()]
        if cmd ~= nil then
            pkt.cols.info:append(" " .. cmd)
        end
        pkt.cols.info:append(" cmd=" .. v_command:le_uint())
        t:add(f_version, v_version)
        t:add(f_opcode, v_opcode)
        t:add(f_priority, v_priority)
        t:add(f_resv, v_resv)
        t:add_le(f_command, v_command)
        t:add_le(f_length, v_length)
        t:add_le(f_id, v_id)
        t:add_le(f_expire, v_expire)
        t:add_le(f_data, v_data)
        return true
    end

    function p_buff.dissector(buf, pkt, root)
        if buff_dissector(buf, pkt, root) then
            --
        else
            data_dis:call(buf, pkt, root)
        end
    end

    local tcp_encap_table = DissectorTable.get("tcp.port")
    tcp_encap_table:add(51000, p_buff)
    tcp_encap_table:add(51001, p_buff)
    tcp_encap_table:add(51002, p_buff)
    tcp_encap_table:add(51003, p_buff)
end
