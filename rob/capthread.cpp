#include "capthread.h"

#include <QDateTime>

CapMgr::CapMgr():
    m_ptimer(nullptr),
    m_istart(false),
    m_padhandle(nullptr)
{

}

void CapMgr::dealStartCap(DevInfo info)
{
    m_pnic = info;
   char errbuf[PCAP_ERRBUF_SIZE]={0};
   //打开适配器
   m_padhandle = pcap_open_live(
       info.name.toStdString().c_str(),  // 设备名
                                 65536,     // 要捕捉的数据包的部分
                                 // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                                 1,         // 混杂模式
                                 1000,      // 读取超时时间
                                 errbuf     // 错误缓冲池
                                 );
       QString str;
       do
       {
           if(m_padhandle == nullptr)
           {
               str = QString::fromLocal8Bit(errbuf,strlen(errbuf));
               break;
           }

           //检查数据链路层，为了简单，只考虑以太网
           if(pcap_datalink(m_padhandle) != DLT_EN10MB)
           {
               str = "Ethernet Only!This program works only on Ethernet networks.";
               break;
           }
           pcap_setnonblock(m_padhandle,0,errbuf);

           if(m_ptimer !=nullptr)
           {
               m_ptimer->stop();
               delete m_ptimer;
               m_ptimer =nullptr;
           }
           m_ptimer = new QTimer;
           m_ptimer->start(10);
           connect(m_ptimer,&QTimer::timeout,this,&CapMgr::readData);
       }while(false);

       emit sendRes(str);
}

void CapMgr::dealStopCap()
{
    m_ptimer->stop();
    m_istart = false;
    if(m_padhandle != nullptr)
    {
        pcap_close(m_padhandle);
        m_padhandle =nullptr;
    }
}

void CapMgr::dealSetFilter(QString strfilter)
{

    m_strfilter = strfilter;
    struct bpf_program fcode;
    const char *packet_filter = strfilter.toStdString().c_str();
    quint32 netmask = 0xffffff;
    if(false == m_pnic.ipAddresses.empty())
    {
        /* 获得接口第一个地址的掩码 */
        for(const auto &a :m_pnic.ipAddresses)
        {
            if(false == a.netmask.isEmpty())
            {
                netmask=ipConvertToInt(a.netmask);
                break;
            }
        }
    }

    QString str;
    do
    {
        int resTemp = pcap_compile(m_padhandle, &fcode, packet_filter, 1, netmask);
        if(resTemp<0)
        {
            str = "Unable to compile the packet filter. Start without filter.";
            break;
        }
        resTemp = pcap_setfilter(m_padhandle, &fcode);
                if(resTemp<0)
        {
            str = "Error setting the filter.";
            break;
        }

    }while(false);
    emit sendFilterRes(str);
}

void CapMgr::packHandler(const pcap_pkthdr *header, uchar *pkt_data)
{
    QString strUsec = QString::number(header->ts.tv_usec).mid(0,2);
    QString strTime = QDateTime::fromSecsSinceEpoch(header->ts.tv_sec).toString("yyyy.MM.dd hh:mm:ss")+strUsec;

    PropertList l = EtherNet_parser(header->len, pkt_data);
    if(l.isEmpty())
    {
        return;
    }
    l <<TcpPPropert{Pro_TIME,"时间",strTime};

    AnsyObj obj;
    QByteArray arr;
    arr.resize(header->len);
    memcpy(arr.data(),pkt_data,header->len);
    obj.pushArr(arr);
    obj.setData(l.getList());
    emit  sendData(obj);
}

PropertList CapMgr::EtherNet_parser(quint32 pktLen, uchar *pkt_data)
{
    /* MAC帧数据：
     *  [ Destination ] [ Source ] [ Type  ] [ Data ] [  FCS  ]
     *  [    6 Bytes  ] [ 6 Bytes] [2 Bytes] -------- [4 Bytes]
     */

    eth_header *eth =  reinterpret_cast<eth_header*>(pkt_data);
    eth->type = ntohs(eth->type);

    PropertList l;
    l<<TcpPPropert{Pro_MAC,"目标MAC",eth->getDestMac()};
    l<<TcpPPropert{Pro_MAC,"源MAC",eth->getStcMac()};

    switch (eth->type) {
    case 0x0806:
        /* ARP */
        l<<ARP_parse(pkt_data+IP_HEADER_OFFSET);
        break;
    case 0x0800:
        /* IPv4 */
        l<<IP_parser(pktLen,pkt_data+IP_HEADER_OFFSET);
        break;
    case 0x86dd:
        /* IPv6 */
        l<<IP6_parser(pktLen, pkt_data+IP_HEADER_OFFSET);
        break;
    default: ;
        l.clear();
        break;
    }
    return l;
}

PropertList CapMgr::ARP_parse(uchar *pkt_data)
{
    arp_header *arp = reinterpret_cast<arp_header*>(pkt_data);
    arp->arp_ntohs();
    /* ARP帧
     *  [硬件类型] [协议类型] [硬件地址长度] [协议地址长度] [   op  ]
     *  [2 Bytes] [2 Bytes] [ 1 Byte  ]  [ 1 Byte   ] [2 Bytes]
     *  [发送端MAC] [发送端IP] [接收方MAC] [接收方IP]
     *  [6 bytes ] [4 bytes] [6 bytes ] [4 bytes]
     */

    PropertList l;
    l<< TcpPPropert{Pro_ARP,"硬件类型",arp->gethwtype()}
    << TcpPPropert{Pro_ARP,"协议类型",arp->getProtType()}
    << TcpPPropert{Pro_ARP,"硬件地址长度",QString::number(arp->ar_hln)}
    << TcpPPropert{Pro_ARP,"协议地址长度",QString::number(arp->ar_pln)}
    << TcpPPropert{Pro_ARP,"操作码",arp->getOp()}
    << TcpPPropert{Pro_ARP,"源MAC",arp->getSrcMac()}
    << TcpPPropert{Pro_ARP,"源IP",arp->getSrcIp()}
    << TcpPPropert{Pro_ARP,"目标MAC",arp->getDestMac()}
    << TcpPPropert{Pro_ARP,"目标IP",arp->getDestIp()};
    return l;
}

PropertList CapMgr::IP_parser(quint32 pktLen, uchar *pkt_data)
{
    ip_header *ipv4 = reinterpret_cast<ip_header *>(pkt_data);
    ipv4->ip_ntohs();

    uint offset = ipv4->ihl*4;
    PropertList l;

    ProType t = Pro_IPV4;
    switch (ipv4->proto) {
    case 1:
        l <<ICMP_parser(pktLen,pkt_data+offset,t);
        break;
    case 6:
        l<<(TCP_parser(pktLen,pkt_data+offset, t));
        break;
    case 17:
        l<<(UDP_parser(pktLen,pkt_data+offset, t));
        break;
    default:
        l<<TcpPPropert{Pro_UNTODO,"IPV4未解析协议",QString::asprintf("0x%x",ipv4->proto)};
        break;
    }


    l<<TcpPPropert{t,"版本",QString::number(ipv4->version)}
    <<TcpPPropert{t,"长度",QString::number(ipv4->ihl)}
    <<TcpPPropert{t,"TOS服务",QString::asprintf("%X",ipv4->tos)}
    <<TcpPPropert{t,"总长度",QString::asprintf("%d",ipv4->tlen)}
    <<TcpPPropert{t,"标识",QString::asprintf("0x%02X",ipv4->id)}
    <<TcpPPropert{t,"片位移",QString::asprintf("0x%02X",ipv4->frag_off)}
    <<TcpPPropert{t,"生存时间",QString::number(ipv4->ttl)}
    <<TcpPPropert{t,"协议",QString::asprintf("0x%X",ipv4->proto)}
    <<TcpPPropert{t,"校验和",QString::asprintf("0x%02x",ipv4->check)}
    <<TcpPPropert{t,"源IP",ipv4->getSrcAddr()}
    <<TcpPPropert{t,"目标IP",ipv4->getDestAddr()}
    <<TcpPPropert{t,"选项等",QString::asprintf("0x%04d",ipv4->op_pad)};
    return  l;
}

PropertList CapMgr::IP6_parser(quint32 pktLen, uchar *pkt_data)
{

    ip6_header *ipv6 = reinterpret_cast<ip6_header *>(pkt_data + IP_HEADER_OFFSET);
    ipv6->plen = ntohs(ipv6->plen);

    PropertList l;
    ProType t = Pro_IPV6;

    switch (ipv6->nh) {
    case 0x3a:
        l<<ICMP_parser(pktLen, pkt_data+sizeof(ip6_header),t);
        break;
    case 0x06:
        //tcp6
        l<<TCP_parser(pktLen,pkt_data+sizeof(ip6_header),t);
        break;
    case 0x11:
        //udp6
        l<<UDP_parser(pktLen,pkt_data+sizeof(ip6_header),t);
        break;
    default :
        l<<TcpPPropert{Pro_UNTODO,"IPV6未解析协议",QString::asprintf("0x%x",ipv6->nh)};
        break;
    }
    l <<TcpPPropert{t,"版本",QString::asprintf("%d",ipv6->version)}
    <<TcpPPropert{t,"流类型",QString::asprintf("0x%04X",ipv6->flowtype)}
    <<TcpPPropert{t,"流标签",QString::asprintf("0x%04X",ipv6->flowid)}
    <<TcpPPropert{t,"有效载荷长度",QString::asprintf("%d",ipv6->plen)}
    <<TcpPPropert{t,"下一个头部",QString::asprintf("0x%04X",ipv6->flowid)}
    <<TcpPPropert{t,"跳限制",QString::asprintf("%d",ipv6->hlim)}
    <<TcpPPropert{t,"源IP",ipv6->getsrcAddr()}
    <<TcpPPropert{t,"目标IP",ipv6->getdestAddr()};
    return l;
}

PropertList CapMgr::ICMP_parser(quint32 pktLen, uchar *pkt_data, qint32 type)
{

    icmp_header* icmp = reinterpret_cast<icmp_header*>(pkt_data);
    icmp->checksum = ntohs(icmp->checksum);

    uint dataLength = pktLen - sizeof(icmp_header);

    ProType   t = (type == 4)?Pro_ICMP6:Pro_ICMP;

    PropertList l;
    l<<TcpPPropert{t,"info",icmp->gettype()}
    <<TcpPPropert{t,"类型",QString::asprintf("0x%X",icmp->type)}
    <<TcpPPropert{t,"代码",QString::asprintf("%d",icmp->code)}
    <<TcpPPropert{t,"校验和",QString::asprintf("0x%02X",icmp->checksum)}
    <<TcpPPropert{t,"len",QString::asprintf("%d",dataLength)};
    return l;
}

PropertList CapMgr::UDP_parser(quint32 pktLen,uchar *pkt_data, qint32 type)
{
    udp_header *udp = reinterpret_cast<udp_header *>(pkt_data);
    udp->udp_noths();

    uint headerlen = sizeof(udp_header);
    QByteArray arr;
    if(udp->len >= headerlen)
    {
        arr.resize(udp->len - headerlen);
        memcpy(arr.data(),pkt_data+headerlen,udp->len - headerlen);
    }

    PropertList l;
    ProType t = (type == 4)?Pro_UDP6:Pro_UDP;
    l<<TcpPPropert{t,"源端口",QString::asprintf("%d",udp->sport)}
    <<TcpPPropert{t,"目标端口",QString::asprintf("%d",udp->dport)}
    <<TcpPPropert{t,"长度",QString::asprintf("%d",udp->len)}
    <<TcpPPropert{t,"校验和",QString::asprintf("0x%02X",udp->crc)}
    <<TcpPPropert{t,"len",QString("%1").arg(udp->len - 8)}
    <<TcpPPropert{t,"data",QString("%1").arg(arr.toHex().toStdString().c_str())};
    return l;
}

PropertList CapMgr::TCP_parser(quint32 pktLen, uchar *pkt_data, qint32 type)
{
    tcp_header *tcp = reinterpret_cast<tcp_header *>(pkt_data);
    tcp->tcp_ntohs();

    uint headerLen = tcp->thl * 4;
    uint dataLength = pktLen - headerLen;

    ProType   t = (type == 4)?Pro_TCP6:Pro_TCP;

    QByteArray arr;
    arr.resize(dataLength);
    memcpy(arr.data(),pkt_data,dataLength);

    PropertList l;
    l<< TcpPPropert{t,"源端口",QString::asprintf("%d",tcp->sport)}
    << TcpPPropert{t,"目标端口", QString::asprintf("%d",tcp->dport)}
    << TcpPPropert{t,"序列号", QString::asprintf("0x%04X",tcp->seq)}
    << TcpPPropert{t,"ACK", QString::asprintf("0x%04X",tcp->ack_seq)}
    << TcpPPropert{t,"头部长度", QString::asprintf("%d",headerLen)}
    << TcpPPropert{t,"标记", tcp->getflag()}
    << TcpPPropert{t,"窗口大小",QString::asprintf("%d",tcp->window)}
    << TcpPPropert{t,"校验和", QString::asprintf("0x%02X",tcp->check)}
    << TcpPPropert{t,"紧急指针",QString::asprintf("Urgent point:%d",tcp->urg_ptr)}
    << TcpPPropert{t,"len",QString::asprintf("%d",dataLength)}
    << TcpPPropert{t,"data",QString("%1").arg(arr.toHex().toUpper().data())};

    if(tcp->dport == 80 || tcp->sport == 80){
         ProType tHttp = (type == 3)?Pro_HTTP:Pro_HTTP6;
         l<< TcpPPropert{tHttp,"http",QString::asprintf("%s",arr.toStdString().c_str())};
    }
    return l;
}





void CapMgr::readData()
{

   do
   {
        struct pcap_pkthdr *header;
        const uchar *pkt_data;
        int  res = pcap_next_ex(m_padhandle, &header, &pkt_data);
        if(res <= 0)
        {
            break;
        }


        //解析
        packHandler(header,const_cast<uchar*>(pkt_data));

   }while(false);
}

quint32 CapMgr::ipConvertToInt(QString ip)
{
    QStringList strList = ip.split(".");
    QByteArray arr;
    arr.append(static_cast<char>(strList[0].toUInt()));
    arr.append(static_cast<char>(strList[1].toUInt()));
    arr.append(static_cast<char>(strList[2].toUInt()));
    arr.append(static_cast<char>(strList[3].toUInt()));
    quint32 uiTemp;
    memcpy(&uiTemp,arr.data(),sizeof(uiTemp));
    return uiTemp;
}
