#include "arp.h"

#include "ethernet.h"
#include "net.h"

#include <stdio.h>
#include <string.h>
/**
 * @brief 初始的arp包
 *
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp) {
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print() {
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip) {
    //初始化缓冲区,arp头部长度为28字节
    buf_init(&txbuf, sizeof(arp_pkt_t));
    //填写ARP报头
    arp_pkt_t *arp_pkt = (arp_pkt_t*)txbuf.data;
    arp_pkt->hw_type16 = swap16(ARP_HW_ETHER);
    arp_pkt->pro_type16 = swap16(NET_PROTOCOL_IP);//IP(0x0800)
    arp_pkt->hw_len = 6;
    arp_pkt->pro_len = 4;
    arp_pkt->opcode16 = swap16(ARP_REQUEST);//apr请求包
    memcpy(arp_pkt->sender_mac, net_if_mac, NET_MAC_LEN);//本机mac地址
    memcpy(arp_pkt->sender_ip, net_if_ip, NET_IP_LEN);//本机ip地址
    memset(arp_pkt->target_mac, 0, NET_MAC_LEN);//请求报文mac填全0
    memcpy(arp_pkt->target_ip, target_ip, NET_IP_LEN);//填入目标IP
    //调用ethernet_out 发送报文
    uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    ethernet_out(&txbuf, broadcast_mac, NET_PROTOCOL_ARP); 

}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac) {
    //初始化txbuf，缓冲区大小为ARP报文头部长度（sizeof(arp_pkt_t)=28字节）
    buf_init(&txbuf, sizeof(arp_pkt_t));
    //填写ARP报头首部（严格遵循ARP协议规范）解析缓冲区为ARP报文结构
    arp_pkt_t *arp_pkt = (arp_pkt_t *)txbuf.data;
    //硬件类型：以太网（1），转换为网络字节序（大端）
    arp_pkt->hw_type16 = swap16(ARP_HW_ETHER);
    //上层协议类型：IPv4（0x0800），转换为网络字节序
    arp_pkt->pro_type16 = swap16(NET_PROTOCOL_IP);
    //MAC地址长度：6字节（标准MAC长度）
    arp_pkt->hw_len = NET_MAC_LEN;
    //IP地址长度：4字节（标准IPv4长度）
    arp_pkt->pro_len = NET_IP_LEN;
    //操作类型：ARP响应（2），转换为网络字节序
    arp_pkt->opcode16 = swap16(ARP_REPLY);

    //发送方MAC/IP：本机的MAC和IP（响应方是本机）
    memcpy(arp_pkt->sender_mac, net_if_mac, NET_MAC_LEN);
    memcpy(arp_pkt->sender_ip, net_if_ip, NET_IP_LEN);

    //目标方MAC/IP：传入的target_mac和target_ip（即ARP请求方的MAC/IP）
    memcpy(arp_pkt->target_mac, target_mac, NET_MAC_LEN);
    memcpy(arp_pkt->target_ip, target_ip, NET_IP_LEN);

    // Step3: 发送ARP报文 调用以太网层发送ARP响应（单播，目标MAC=请求方MAC，协议类型=ARP）
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac) {
    //长度比arp头部小
    if (buf->len < sizeof(arp_pkt_t)) {
        return; // 数据包不完整，丢弃
    }
    arp_pkt_t *arp_pkt = (arp_pkt_t *)buf->data;
    //检测硬件类型是否为以太网类型
    if (swap16(arp_pkt->hw_type16) != ARP_HW_ETHER) {
        return;
    }
    if (swap16(arp_pkt->pro_type16) != NET_PROTOCOL_IP) {
        return;//上层协议类型：必须是IPv4（0x0800）
    }
    if (arp_pkt->hw_len != NET_MAC_LEN) {
        return;//MAC地址长度：必须是6字节
    }
    if (arp_pkt->pro_len != NET_IP_LEN) {
        return;//IP地址长度：必须是4字节
    }
    //操作类型：仅处理ARP_REQUEST或ARP_REPLY，转换为主机字节序
    uint16_t opcode = swap16(arp_pkt->opcode16);
    if (opcode != ARP_REQUEST && opcode != ARP_REPLY) {
        return;
    }
    //更新ARP表项
    map_set(&arp_table, arp_pkt->sender_ip, arp_pkt->sender_mac);
    //检查arp_buf缓存情况
    buf_t *cached_buf = map_get(&arp_buf, arp_pkt->sender_ip);
    // 情况1：有缓存 → 发送缓存的IP数据包，并删除缓存
    if (cached_buf != NULL) {
        // 调用以太网层发送缓存的IP数据包（目标MAC=发送方MAC）
        ethernet_out(cached_buf, arp_pkt->sender_mac, NET_PROTOCOL_IP);
        // 删除缓存，避免重复发送
        map_delete(&arp_buf, arp_pkt->sender_ip);
        return;
    }
    // 情况2：无缓存 → 判断是否是请求本机MAC的ARP_REQUEST
    // 条件1：操作类型是ARP_REQUEST；条件2：目标IP是本机IP
    if (opcode == ARP_REQUEST && !memcmp(arp_pkt->target_ip, net_if_ip, NET_IP_LEN)) {
        // 回应ARP响应报文
        arp_resp(arp_pkt->sender_ip, arp_pkt->sender_mac);
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 */
void arp_out(buf_t *buf, uint8_t *ip) {
    //查找 ARP 表,依据 IP 地址在 ARP 表（arp_table）中进行查找
    uint8_t *dst_mac = map_get(&arp_table, ip);
    //找到对应 MAC 地址：若能找到该IP地址对应的MAC地址，则将数据包直接发送给以太网层，即调用ethernet_out函数将数据包发出。
    if( dst_mac != NULL){
        ethernet_out(buf, dst_mac, NET_PROTOCOL_IP);
        return;
    }
    //未找到对应mac地址
    void* cached_buf = map_get(&arp_buf , ip);//寻找是否存在arp_buf是否已经缓存 
    if (cached_buf != NULL) {
        // 已有缓存包，说明正在等待ARP响应 ，则不可重复发送ARP请求，直接返回
        return;
    }
    //没有缓存包，则缓存该ip层数据包到arp_buf，避免丢包
    map_set(&arp_buf, ip, buf);
    //发送ARP请求，查询目标ip的mac地址
    arp_req(ip);
}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init() {
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, NULL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}