#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"



/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    // Step1: 检查数据包长度 若数据包长度 < IP头部最小长度（20字节），判定为不完整，直接丢弃
    if (buf->len < IP_MIN_HDR_LEN) {
        return;
    }

    // 解析IP头部（适配自定义ip_hdr_t结构体）
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;

    // Step2: 报头合法性检测 
    // 2.1 校验版本号：必须为IPv4
    if (ip_hdr->version != IP_VERSION_4) {
        return;
    }

    // 2.2 校验头部长度：合法IP头部长度≥5（20字节），且≤15（60字节）
    if (ip_hdr->hdr_len < IP_HDR_LEN || ip_hdr->hdr_len > 15) {
        return;
    }
    uint16_t actual_hdr_len = ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE; // 实际头部字节长度

    // 2.3 校验总长度：IP头总长度字段 ≤ 收到的数据包长度，且总长度 ≥ 头部实际长度
    uint16_t ip_total_len = swap16(ip_hdr->total_len16); // 转主机字节序
    if (ip_total_len > buf->len || ip_total_len < actual_hdr_len) {
        return;
    }

    // Step3: 校验头部校验和 
    // 3.1 保存原始校验和
    uint16_t orig_checksum = ip_hdr->hdr_checksum16;
    // 3.2 将校验和字段置0
    ip_hdr->hdr_checksum16 = 0;
    // 3.3 重新计算头部校验和（计算范围：实际IP头部长度）
    uint16_t calc_checksum = checksum16((uint16_t *)ip_hdr, actual_hdr_len);
    // 3.4 对比计算结果与原始校验和，不一致则丢弃；一致则恢复原始校验和
    if (calc_checksum != orig_checksum) {
        return;
    }
    ip_hdr->hdr_checksum16 = orig_checksum;

    // Step4: 对比目的IP地址 
    // 检查目的IP是否为本机IP，非本机则丢弃
    if (memcmp(ip_hdr->dst_ip, net_if_ip, NET_IP_LEN) != 0) {
        return;
    }

    //  Step5: 去除填充字段 
    // 若数据包实际长度 > IP总长度字段，说明存在填充，移除多余部分
    if (buf->len > ip_total_len) {
        buf_remove_padding(buf, buf->len - ip_total_len);
    }

    //  Step6: 去掉IP报头 
    // 移除IP头部，缓冲区剩余数据为上层协议载荷
    buf_remove_header(buf, actual_hdr_len);

    // Step7: 向上层传递数据包 
    // 调用net_in向上层传递数据包，返回值表示是否识别该协议类型
    int ret = net_in(buf, ip_hdr->protocol,ip_hdr->src_ip);

    // 若上层不识别该协议，返回ICMP协议不可达（需恢复IP头部后发送）
    if (ret == -1) {
        // 恢复IP头部（为发送ICMP报文做准备）
        buf_add_header(buf, actual_hdr_len);
        // 调用ICMP不可达函数，返回协议不可达信息
        icmp_unreachable(buf, ip_hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
}
/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    // Step1: 增加IP头部缓存空间 基础IP头部长度 = 5 * IP_HDR_LEN_PER_BYTE = 5*4=20字节
    buf_add_header(buf, IP_HDR_LEN * IP_HDR_LEN_PER_BYTE);
    
    // 解析IP头部结构体（适配自定义的ip_hdr_t）
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;

    // Step2: 填写IP头部字段 
    // 1. 版本号(4位) + 首部长度(4位)：版本=IPv4，首部长度=5（20字节）
    ip_hdr->version = IP_VERSION_4;
    ip_hdr->hdr_len = IP_HDR_LEN;
    // 2. 服务类型：默认0
    ip_hdr->tos = IP_DEFAULT_TOS;
    // 3. 总长度：IP头部 + 数据总长度（转网络字节序）
    ip_hdr->total_len16 = swap16(buf->len);
    // 4. 标识符：分片唯一标识（转网络字节序）
    ip_hdr->id16 = swap16(id);
    // 5. 标志与分段：MF位 + 分片偏移（偏移转换为8字节单位，转网络字节序）
    uint16_t flags_fragment = 0;
    if (mf) {
        flags_fragment |= IP_MORE_FRAGMENT; // 设置MF位（有更多分片）
    }
    flags_fragment |= (offset / IP_HDR_OFFSET_PER_BYTE); // 偏移转换为8字节单位
    ip_hdr->flags_fragment16 = swap16(flags_fragment);
    // 6. 存活时间：默认64
    ip_hdr->ttl = IP_DEFAULT_TTL;
    // 7. 上层协议类型（如NET_PROTOCOL_ICMP/NET_PROTOCOL_TCP等）
    ip_hdr->protocol = protocol;
    // 8. 源IP地址：本机IP
    memcpy(ip_hdr->src_ip, net_if_ip, NET_IP_LEN);
    // 9. 目标IP地址：传入的目的IP
    memcpy(ip_hdr->dst_ip, ip, NET_IP_LEN);
    // 10. 首部校验和：先置0，后续计算
    ip_hdr->hdr_checksum16 = 0;

    // Step3: 计算并填写校验和 计算范围：仅IP头部（20字节），结果填回校验和字段
    ip_hdr->hdr_checksum16 = checksum16((uint16_t *)ip_hdr, IP_HDR_LEN * IP_HDR_LEN_PER_BYTE);

    //Step4: 发送数据 交给ARP层处理IP→MAC映射，最终通过以太网发送
    arp_out(buf, ip);
}
// 全局IP标识
static uint16_t ip_id = 0;
/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    // Step1: 检查数据报包长
    size_t payload_len = buf->len; // 上层数据长度（IP载荷）
    int need_fragment = (payload_len > IP_MAX_PAYLOAD); // 是否需要分片

    // Step2: 分片处理 
    if (need_fragment) {
        // 生成唯一IP标识（所有分片共用）
        uint16_t cur_id = ip_id++;
        // 已发送的载荷长度
        size_t sent_len = 0;
        // 分片偏移（字节单位）
        uint16_t fragment_offset = 0;

        // 发送除最后一个外的所有分片（每个分片载荷=IP_MAX_PAYLOAD）
        while (sent_len + IP_MAX_PAYLOAD < payload_len) {
            // Step2.1 初始化分片缓冲区
            buf_t frag_buf;
            buf_init(&frag_buf, IP_MAX_PAYLOAD);
            // 拷贝当前分片数据
            memcpy(frag_buf.data, buf->data + sent_len, IP_MAX_PAYLOAD);
            frag_buf.len = IP_MAX_PAYLOAD;

            // Step2.2 发送分片（MF=1，有更多分片）
            ip_fragment_out(&frag_buf, ip, protocol, cur_id, fragment_offset, 1);

            // 更新已发送长度和分片偏移
            sent_len += IP_MAX_PAYLOAD;
            fragment_offset += IP_MAX_PAYLOAD;
        }

        // 发送最后一个分片
        size_t last_frag_len = payload_len - sent_len;
        if (last_frag_len > 0) {
            // Step2.3 初始化最后一个分片缓冲区
            buf_t last_frag_buf;
            buf_init(&last_frag_buf, last_frag_len);
            memcpy(last_frag_buf.data, buf->data + sent_len, last_frag_len);
            last_frag_buf.len = last_frag_len;

            // Step2.4 发送最后一个分片（MF=0，无更多分片）
            ip_fragment_out(&last_frag_buf, ip, protocol, cur_id, fragment_offset, 0);
        }
    }
    // Step3: 直接发送（无需分片）
    else {
        // 生成唯一IP标识
        uint16_t cur_id = ip_id++;
        // 直接调用ip_fragment_out发送完整包（偏移=0，MF=0）
        ip_fragment_out(buf, ip, protocol, cur_id, 0, 0);
    }
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}