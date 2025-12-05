#include "icmp.h"

#include "ip.h"
#include "net.h"

/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip) {
    // Step1: 初始化并封装数据 
    // 1. 初始化txbuf，大小为请求包长度（ICMP头部+数据完整复用）
    buf_init(&txbuf, req_buf->len);
    // 2. 拷贝请求包的全部数据（ICMP头部+数据）到响应缓冲区
    memcpy(txbuf.data, req_buf->data, req_buf->len);
    // 解析ICMP响应头部
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)txbuf.data;
    // 3. 修改ICMP类型为回显应答（保持其他字段与请求一致：id/seq/code/数据）
    icmp_hdr->type = ICMP_TYPE_ECHO_REPLY;
    icmp_hdr->code = 0; // 回显应答代码固定为0
    icmp_hdr->checksum16 = 0; // 先置0，后续计算校验和

    // Step2: 填写校验和 
    // 调用checksum16计算整个ICMP报文的校验和（头部+数据）
    icmp_hdr->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len);

    // Step3: 发送数据报 
    // 调用ip_out发送ICMP响应，目标IP为请求方IP，上层协议为ICMP
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip) {
    // Step1: 报头检测（校验数据包完整性）若数据包长度 < ICMP头部最小长度（8字节），判定为不完整，直接丢弃
    if (buf->len < sizeof(icmp_hdr_t)) {
        return;
    }

    // 解析ICMP头部
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)buf->data;

    // Step2: 查看ICMP类型 仅处理回显请求（ICMP_TYPE_ECHO_REQUEST = 8）类型的报文
    if (icmp_hdr->type != ICMP_TYPE_ECHO_REQUEST) {
        return; // 非回显请求，无需处理
    }
    // Step3: 回送回显应答 调用icmp_resp发送回显响应，传入请求包和源IP（响应目标为请求方IP）
    icmp_resp(buf, src_ip);
}

/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code) {
    // Step1: 初始化并填写ICMP报头 
    // 1. 计算ICMP报文总长度：ICMP头(8字节) + IP头(至少20字节) + IP载荷前8字节
    size_t ip_hdr_len = ((ip_hdr_t *)recv_buf->data)->hdr_len * IP_HDR_LEN_PER_BYTE; // 实际IP头长度
    size_t icmp_data_len = ip_hdr_len + 8; // ICMP数据部分长度（IP头 + 载荷前8字节）
    size_t icmp_total_len = sizeof(icmp_hdr_t) + icmp_data_len; // ICMP总长度

    // 2. 初始化txbuf，大小为ICMP总长度
    buf_init(&txbuf, icmp_total_len);

    // 3. 解析ICMP头部并填写核心字段
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)txbuf.data;
    icmp_hdr->type = ICMP_TYPE_UNREACH;    // 类型：目的不可达(3)
    icmp_hdr->code = code;                 // 代码：协议不可达(2)或端口不可达(3)
    icmp_hdr->checksum16 = 0;              // 先置0，后续计算校验和
    icmp_hdr->id16 = 0;                    // 不可达报文无需id/seq，置0即可
    icmp_hdr->seq16 = 0;

    // Step2: 填写数据与校验和 
    // 1. 填写ICMP数据部分：IP头 + IP载荷前8字节
    uint8_t *icmp_data = txbuf.data + sizeof(icmp_hdr_t); // ICMP数据部分起始地址
    // 拷贝IP头部（完整）
    memcpy(icmp_data, recv_buf->data, ip_hdr_len);
    // 拷贝IP载荷前8字节（若载荷不足8字节则拷贝全部）
    size_t payload_copy_len = (recv_buf->len - ip_hdr_len) >= 8 ? 8 : (recv_buf->len - ip_hdr_len);
    memcpy(icmp_data + ip_hdr_len, recv_buf->data + ip_hdr_len, payload_copy_len);
    // 若载荷不足8字节，剩余部分置0（保证总长度）
    if (payload_copy_len < 8) {
        memset(icmp_data + ip_hdr_len + payload_copy_len, 0, 8 - payload_copy_len);
    }
    // 2. 计算整个ICMP报文的校验和（头部+数据）
    icmp_hdr->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len);
    //  Step3: 发送数据报 
    // 调用ip_out发送ICMP不可达报文，目标IP为原IP包的发送方，上层协议为ICMP
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}