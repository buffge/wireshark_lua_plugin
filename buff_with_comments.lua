do
    -- 定义协议
    local p_buff = Proto("buff", "buffge buff")
    -- 定义封包中的字段
    local f_version = ProtoField.uint8("buff.version", "version", base.DEC)
    local f_opcode = ProtoField.uint8("buff.opcode", "opcode", base.DEC)
    local f_priority = ProtoField.uint8("buff.priority", "priority", base.HEX)
    local f_resv = ProtoField.uint8("buff.resv", "resv", base.HEX)
    local f_command = ProtoField.uint16("buff.command", "command", base.DEC)
    local f_length = ProtoField.uint16("buff.length", "length", base.DEC)
    local f_id = ProtoField.uint64("buff.id", "id", base.HEX)
    local f_expire = ProtoField.uint64("buff.expire", "expire", base.DEC)
    --上面八个是header字段 data 是封包传递的数据
    local f_data = ProtoField.string("buff.data", "data", base.UNICODE)
    p_buff.fields = {
        f_version, f_opcode, f_priority, f_resv, f_command,
        f_length, f_id, f_expire, f_data
    }
    -- 定义一个 int -> 字符串 在info中展示用
    local cmdMap = {
        [1] = "ping",
        [2] = "pong",
        [3] = "用户上线"
    }
    local data_dis = Dissector.get("data")
    -- 定义协议解析函数
    local function buff_dissector(buf, pkt, root)
        -- 获取包大小
        local buf_len = buf:len();
        --如果小于24(上面header中所有字段的总长度) 则不是buff协议
        if buf_len < 24 then
            return false
        end
        --获取包的第一个字节 如果不是1 则不是buff协议
        local v_version = buf(0, 1)
        if (v_version:uint() ~= 0x01) then
            return false
        end
        -- 取出封包中的各个字段实际的值
        local v_opcode = buf(1, 1)
        local v_priority = buf(2, 1)
        local v_resv = buf(3, 1)
        local v_command = buf(4, 2)
        local v_length = buf(6, 2)
        -- 如果header中length的值 不等于 总封包长度 - 头长度(24) 则不是buff协议
        if (v_length:le_uint() ~= (buf_len - 24)) then
            return false
        end
        local v_id = buf(8, 8)
        local v_expire = buf(16, 8)
        local v_data = buf(24, buf_len - 24):string(ENC_UTF_8)
        --buff 协议详情 点击某条消息可以看到每个字段详情
        local t = root:add(p_buff, buf)
        -- 设置列的协议展示名称
        pkt.cols.protocol = "buff"
        -- 设置info 列的展示信息
        pkt.cols.info:set(pkt.src_port .. " -> " .. pkt.dst_port)
        -- 将header中的command 映射为可读字符串 并加入到info列中
        local cmd = cmdMap[v_command:le_uint()]
        if cmd ~= nil then
            pkt.cols.info:append(" " .. cmd)
        end
        -- 将 command 信息添加到info中中
        pkt.cols.info:append(" cmd=" .. v_command:le_uint())
        -- 设置每个字段的值
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
     -- 定义buff协议解析函数
    function p_buff.dissector(buf, pkt, root)
        -- 如果解析不成功则调用默认解析器
        if buff_dissector(buf, pkt, root) then
            --
        else
            data_dis:call(buf, pkt, root)
        end
    end
    local tcp_encap_table = DissectorTable.get("tcp.port")
    -- 监听 tcp 的20000-20003端口
    tcp_encap_table:add(20000, p_buff)
    tcp_encap_table:add(20001, p_buff)
    tcp_encap_table:add(20002, p_buff)
    tcp_encap_table:add(20003, p_buff)
end
