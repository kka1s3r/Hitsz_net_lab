#include "udp.h"

#include "icmp.h"
#include "ip.h"

/**
 * @brief udp处理程序表
 *
 */
map_t udp_table;

/**
 * @brief 处理一个收到的udp数据包
 *
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void udp_in(buf_t *buf, uint8_t *src_ip) {
    // Step1: 包检查 
    // 1.1 检查数据包长度是否小于UDP头部长度（8字节）
    if (buf->len < sizeof(udp_hdr_t)) {
        return;
    }
    // 解析UDP头部
    udp_hdr_t *udp_hdr = (udp_hdr_t *)buf->data;
    // 1.2 转换UDP总长度为主机字节序，检查实际长度是否小于头部声明的长度
    uint16_t udp_total_len = swap16(udp_hdr->total_len16);
    if (buf->len < udp_total_len) {
        return;
    }
    // 裁剪缓冲区至UDP声明的总长度（去除多余填充字节）
    if (buf->len > udp_total_len) {
        buf_remove_padding(buf, buf->len - udp_total_len);
    }
    // ===================== Step2: 重新计算校验和 =====================
    // 2.1 保存原始校验和
    uint16_t orig_checksum = udp_hdr->checksum16;
    // 2.2 将校验和字段置0
    udp_hdr->checksum16 = 0;
    // 2.3 调用transport_checksum重新计算校验和（含伪头部）
    uint16_t calc_checksum = transport_checksum(NET_PROTOCOL_UDP, buf, src_ip, net_if_ip);
    // 2.4 对比校验和，不一致则丢弃
    if (calc_checksum != orig_checksum) {
        // 恢复原始校验和（不影响后续逻辑，仅保证缓冲区数据完整性）
        udp_hdr->checksum16 = orig_checksum;
        return;
    }
    // 恢复原始校验和
    udp_hdr->checksum16 = orig_checksum;
    // ===================== Step3: 查询处理函数 =====================
    // 转换目的端口为主机字节序，查询udp_table
    uint16_t dst_port = swap16(udp_hdr->dst_port16);
    udp_handler_t *handler = map_get(&udp_table, &dst_port);
    // ===================== Step4: 未找到处理函数（端口不可达） =====================
    if (handler == NULL) {
        // 4.1 为缓冲区添加IP头部空间（ICMP不可达需要原始IP头）
        buf_add_header(buf, IP_HDR_LEN * IP_HDR_LEN_PER_BYTE);
        // 4.2 发送端口不可达的ICMP报文（code=ICMP_CODE_PORT_UNREACH）
        icmp_unreachable(buf, src_ip, ICMP_CODE_PORT_UNREACH);
        return;
    }
    // ===================== Step5: 调用处理函数 =====================
    // 5.1 去掉UDP头部，缓冲区仅保留上层数据
    buf_remove_header(buf, sizeof(udp_hdr_t));
    // 5.2 转换源端口为主机字节序
    uint16_t src_port = swap16(udp_hdr->src_port16);
    // 5.3 调用注册的处理函数，传递数据、长度、源IP、源端口
    (*handler)(buf->data, buf->len, src_ip, src_port);
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的包
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port) {
    // Step1: 添加UDP报头 
    // UDP头部长度为8字节，为缓冲区添加头部空间
    buf_add_header(buf, sizeof(udp_hdr_t));
    
    // 解析UDP头部结构体
    udp_hdr_t *udp_hdr = (udp_hdr_t *)buf->data;

    //  Step2: 填充UDP首部字段 
    // 1. 源端口（转网络字节序）
    udp_hdr->src_port16 = swap16(src_port);
    // 2. 目的端口（转网络字节序）
    udp_hdr->dst_port16 = swap16(dst_port);
    // 3. UDP总长度（头部+数据，转网络字节序）
    udp_hdr->total_len16 = swap16(buf->len);
    // 4. 校验和先置0，后续计算
    udp_hdr->checksum16 = 0;

    // Step3: 计算并填充校验和 
    // 调用transport_checksum计算UDP校验和（含伪头部）
    udp_hdr->checksum16 = transport_checksum(NET_PROTOCOL_UDP, buf, net_if_ip, dst_ip);

    // Step4: 发送UDP数据报 
    // 调用ip_out发送，上层协议指定为UDP
    ip_out(buf, dst_ip, NET_PROTOCOL_UDP);
}

/**
 * @brief 初始化udp协议
 *
 */
void udp_init() {
    map_init(&udp_table, sizeof(uint16_t), sizeof(udp_handler_t), 0, 0, NULL, NULL);
    net_add_protocol(NET_PROTOCOL_UDP, udp_in);
}

/**
 * @brief 打开一个udp端口并注册处理程序
 *
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int udp_open(uint16_t port, udp_handler_t handler) {
    return map_set(&udp_table, &port, &handler);
}

/**
 * @brief 关闭一个udp端口
 *
 * @param port 端口号
 */
void udp_close(uint16_t port) {
    map_delete(&udp_table, &port);
}

/**
 * @brief 发送一个udp包
 *
 * @param data 要发送的数据
 * @param len 数据长度
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port) {
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dst_ip, dst_port);
}