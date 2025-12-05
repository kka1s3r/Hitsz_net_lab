#include "ethernet.h"

#include "arp.h"
#include "driver.h"
#include "ip.h"
#include "utils.h"
/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf) {
    //如果数据包有效数据大小小于14，说明不包含以太网头部（14B)
    if(buf->len < sizeof(ether_hdr_t))
        return;//丢弃无效帧
    //解析以太网头部
    ether_hdr_t *ehdr = (ether_hdr_t*) buf -> data;
    //保存源mac地址
    uint8_t src_mac[6];
    for (int i = 0; i < 6; i++) {
        src_mac[i] = ehdr->src[i];
    }
    //剥离以太网头部，传递给上层协议
    buf_remove_header(buf,sizeof(ether_hdr_t)); 
    //转为大端序
    uint16_t protocol = swap16(ehdr->protocol16);
    //根据据协议类型分发到上层
    net_in(buf,protocol,src_mac);
}
/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol) {
    //如果长度不到46字节，则填充0
    if(buf->len < ETHERNET_MIN_TRANSPORT_UNIT){
        buf_add_padding(buf , ETHERNET_MIN_TRANSPORT_UNIT - buf->len);
    }
    //添加以太网包头
    buf_add_header(buf,sizeof(ether_hdr_t));
    ether_hdr_t *hdr = (ether_hdr_t *)buf -> data;
    //填写目的mac地址
    for(int i = 0 ; i < 6 ; i++ ){
        hdr->dst[i] = mac[i];
    }
    //填写源mac地址
    for(int i = 0 ;i < 6 ; i++){
        hdr->src[i] = net_if_mac[i];
    }
    //填写protocol
    hdr->protocol16 = swap16(protocol);
    //调用驱动层函数发送完整的以太网帧
    driver_send(buf);
}
/**
 * @brief 初始化以太网协议
 *
 */
void ethernet_init() {
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 *
 */
void ethernet_poll() {
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
