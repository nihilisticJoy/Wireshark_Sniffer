#ifndef ROB_H
#define ROB_H

#include "pcap.h"
#ifdef __linux__
#include <arpa/inet.h>
#endif

#include "common/singleton.h"
#include <QString>
#include <QList>
#include <QtDebug>


struct Address {

    QString saFamily;  // IP Address Family Name
    QString ipAddr;    // IP Address
    QString netmask;    // Netmask
    QString broadAddr;  // Broadcast Address
    QString dstAddr;    // Destination Address
};

struct DevInfo {
    QString name;       //设备名(Name)
    QString description;        // 设备描述(Description)
    QString loopbackAddr;       // Loopback Address
    QList<Address> ipAddresses;   // IP Address
};


//定义为小端
#define LITTLE_ENDIAN
#define IP_HEADER_OFFSET 14


#pragma pack(push)
#pragma pack(1)                 //单字节对齐


//MAC 帧头部， Ethernet II 协议报头
struct eth_header
{
    quint8 dest[6];          //6个字节 目标地址
    quint8 src[6];			//6个字节 源地址
    quint16 type;			//2个字节 类型

    QString getStcMac()
    {
        return QString::asprintf("%02X:%02X:%02X:%02X:%02X:%02X",dest[0],dest[1],dest[2],dest[3],dest[4],dest[5]);
    }

    QString getDestMac()
    {
      return QString::asprintf("%02X:%02X:%02X:%02X:%02X:%02X",src[0],src[1],src[2],src[3],src[4],src[5]);
    }
};


//ARP 协议头部
struct arp_header
{
    ushort ar_hw;						//硬件类型
    ushort ar_prot;						//协议类型
    uchar ar_hln;						//硬件地址长度
    uchar ar_pln;						//协议地址长度
    ushort ar_op;						//操作码，1为请求 2为回复
    uchar ar_srcmac[6];			//发送方MAC
    uchar ar_srcip[4];				//发送方IP
    uchar ar_destmac[6];			//接收方MAC
    uchar ar_destip[4];				//接收方IP

    void arp_ntohs()
    {
        this->ar_hw = ntohs(this->ar_hw);
        this->ar_prot = ntohs(this->ar_prot);
        this->ar_op = ntohs(this->ar_op);
    }

    QString gethwtype()
    {
        return  QString::asprintf("%02X",ar_hw);
    }

    QString getProtType()
    {
        QString protType;
        switch (this->ar_prot)
        {
        case 0x0806:
            /* ARP */
            protType = "ARP(0x0806)";
            break;
        case 0x0800:
            /* IPv4 */
            protType = "IPv4 (0x0800)";
            break;
        case 0x86dd:
            /* IPv6 */
            protType = "IPv6 (0x86dd)";
            break;
        default:
            protType = QString::asprintf("Protocol Type: %02X",ar_prot);
            break;
        }
        return protType;
    }

    QString getOp()
    {
       return  (ar_op == 0x1)?QString("request (0x01)"):QString("response (0x02)");
    }

    QString getSrcMac()
    {
         return QString::asprintf("%02X-%02X-%02X-%02X-%02X-%02X",ar_srcmac[0],ar_srcmac[1],ar_srcmac[2],ar_srcmac[3],ar_srcmac[4],ar_srcmac[5]);
    }
    QString getDestMac()
    {
        return QString::asprintf("%02X-%02X-%02X-%02X-%02X-%02X",ar_destmac[0],ar_destmac[1],ar_destmac[2],ar_destmac[3],ar_destmac[4],ar_destmac[5]);

    }
    QString getSrcIp()
    {
         return QString::asprintf("%d.%d.%d.%d",ar_srcip[0],ar_srcip[1],ar_srcip[2],ar_srcip[3]);
    }
    QString getDestIp()
    {
        return QString::asprintf("%d.%d.%d.%d",ar_destip[0],ar_destip[1],ar_destip[2],ar_destip[3]);
    }
};


//定义IPv4头
struct ip_header
{
#if defined(LITTLE_ENDIAN)
    uchar ihl:4;           //长度
    uchar version:4;       //版本
#elif defined(BIG_ENDIAN)
    uchar version:4;
    uchar  ihl:4;
#endif
    uchar tos;				//TOS 服务类型
    ushort tlen;			//包总长 u_short占两个字节
    ushort id;				//标识
    ushort frag_off;	//片位移
    uchar ttl;				//生存时间
    uchar proto;		//协议
    ushort check;		//校验和
    uchar saddr[4];			//源地址
    uchar daddr[4];			//目的地址
    uint	op_pad;		//选项等

    void ip_ntohs()
    {
        this->tlen = ntohs(this->tlen);
        this->id = ntohs(this->id);
        this->check = ntohs(this->check);
        this->frag_off = ntohs(this->frag_off);
    }
    QString getSrcAddr()
    {
        return QString::asprintf("%d.%d.%d.%d",saddr[0],saddr[1],saddr[2],saddr[3]);
    }
    QString getDestAddr()
    {
        return QString::asprintf("%d.%d.%d.%d",daddr[0],daddr[1],daddr[2],daddr[3]);
    }
};


//定义IPv6
struct ip6_header
{
    uint version:4,	//版本
    flowtype:8,			//流类型
    flowid:20;				//流标签
    ushort plen;					//有效载荷长度
    uchar nh;						//下一个头部
    uchar hlim;					//跳限制
    ushort saddr[8];			//源地址
    ushort daddr[8];			//目的地址

    QString getsrcAddr()
    {
        return QString::asprintf("%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",saddr[0],saddr[1],saddr[2],saddr[3],saddr[4],saddr[5],saddr[6],saddr[7]);
    }

    QString getdestAddr()
    {
        return QString::asprintf("%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",daddr[0],daddr[1],daddr[2],daddr[3],daddr[4],daddr[5],daddr[6],daddr[7]);

    }
};

//定义ICMP
struct icmp_header
{
    uchar type;			//8位 类型
    uchar code;			//8位 代码
    ushort checksum;			//校验和 16位

    QString gettype()
    {
        QString str;
        if(type == 0){
            str = "Echo (ping) Reply";
        }else if(type == 8){
            str = "Echo (ping) Request";
        }else if(type == 1){
            str = "Time out";
        }
        return str;
    }
};

//定义ICMPv6
struct icmp6_header
{
    uchar type;			//8位 类型
    uchar code;			//8位 代码
    ushort checksum;			//校验和 16位

    QString gettype()
    {
        QString str;
        if(type == 0){
            str = "Echo (ping) Reply";
        }else if(type == 8){
            str = "Echo (ping) Request";
        }else if(type == 1){
            str = "Time out";
        }
        return str;
    }
};

//定义TCP头
struct tcp_header
{
    ushort sport;							//源端口地址  16位
    ushort dport;							//目的端口地址 16位
    uint seq;									//序列号 32位
    uint ack_seq;							//确认序列号
#if defined(LITTLE_ENDIAN)
    uchar  reserved_1:4;   //保留6位中的4位首部长度
    uchar  thl:4;          //tcp头部长度
    uchar  flag:6;         //6位标志
    uchar  reseverd_2:2;   //保留6位中的2位
#elif defined(BIG_ENDIAN)
    u_char  thl:4;              //tcp头部长度
    u_char  reserved_1:4;   //保留6位中的4位首部长度
    u_char  reseverd_2:2;   //保留6位中的2位
    u_char  flag:6;         //6位标志
#endif
    ushort window;					//窗口大小 16位
    ushort check;						//校验和 16位
    ushort urg_ptr;					//紧急指针 16位
    uint opt;								//选项
    void tcp_ntohs()
    {
        this->sport = ntohs(this->sport);
        this->dport = ntohs(this->dport);
        this->check = ntohs(this->check);
    }

    QString getflag()
    {
        //FIN标志，表示通知对方本端要关闭连接了。我们称携带FIN标志的TCP报文段为 **结束报文段**。
        //SYN标志，表示请求建立一个连接。我们称携带SYN标志的TCP报文段为**同步报文段**。
        //RST标志，表示要求对方重新建立连接。我们称携带RST标志的TCP报文段为**复位报文段**。
        //PSH标志，提示接收端应用程序应该立即从TCP接收缓冲区中读走数据，为接收后续数据腾出空间（如果应用程序不将接收到的数据读走，它们就会一直停留在TCP接收缓冲区中）。
        //ACK标志，表示确认号是否有效。我们称携带ACK标识的TCP报文段为**确认报文段**。
        //URG标志，表示紧急指针（urgent pointer）是否有效。

       return QString::asprintf("fin:%d syn:%d rst:%d psh:%d ack:%d urg:%d",
                                flag & 0x01,
                                flag>>1& 0x01,
                                flag>>2& 0x01,
                                flag>>3& 0x01,
                                flag>>4& 0x01,
                                flag>>5& 0x01);
    }
};


//UDP 首部
struct udp_header
{
    ushort sport;          // 源端口(Source port)
    ushort dport;          // 目的端口(Destination port)
    ushort len;            // UDP数据包长度(Datagram length)
    ushort crc;            // 校验和(Checksum)

    void udp_noths()
    {
        this->sport = ntohs( this->sport );
        this->dport = ntohs( this->dport );
        this->len = ntohs( this->len );
        this->crc = ntohs( this->crc );
    }
};
#pragma pack(pop)
#endif // ROB_H
