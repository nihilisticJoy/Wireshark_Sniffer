#include "netmgr.h"

#include "rob/netmgr.h"
NetMgr::NetMgr()
{
    m_uitcp4Size = 0;
    m_uiudp4Size = 0;
    m_uitcp6Size = 0;
    m_uiudp6Size = 0;
}

void NetMgr::clearAnsy()
{
    m_uitcp4Size = 0;
    m_uiudp4Size = 0;
    m_uitcp6Size = 0;
    m_uiudp6Size = 0;
}

QVector<DevInfo> NetMgr::getNicInfo()
{
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE+1];
    QVector<DevInfo> nicVector;

    /* 获得接口列表 */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        return nicVector;
    }

    /* 扫描列表并打印每一项 */
    pcap_if_t *d=alldevs;
    for(;d!=nullptr;d = d->next)
    {
        auto *ptr =getInfo(d);
        nicVector.append(*ptr);
    }

    pcap_freealldevs(alldevs);
    return nicVector;
}

quint64 NetMgr::getDataSum()
{
    return m_uitcp4Size +m_uiudp4Size + m_uitcp6Size + m_uiudp6Size;
}




QString NetMgr::ip4tostr(sockaddr *addr)
{
    auto  ulip=  reinterpret_cast<sockaddr_in*>(addr)->sin_addr;
    quint8 *p = reinterpret_cast<quint8*>(&ulip);
    return  QString::asprintf("%d.%d.%d.%d",p[0],p[1],p[2],p[3]);
}

QString NetMgr::ip6tostr(sockaddr *addr)
{
    auto  ulip=  reinterpret_cast<sockaddr_in*>(addr)->sin_addr;
    quint8 *p = reinterpret_cast<quint8*>(&ulip);
    return  QString::asprintf("%X:%X:%X:%X:%X:%X",p[0],p[1],p[2],p[3],p[4],p[5]);
}



/* 获取所有可用信息 */
DevInfo* NetMgr::getInfo(pcap_if_t *d)
{


    DevInfo * devs = new DevInfo;
    /* 设备名(Name) */
    devs->name = d->name;

    /* 设备描述(Description) */
    if (d->description)
    {
        devs->description = d->description;
    }

    /* Loopback Address*/
    devs->loopbackAddr = (d->flags & PCAP_IF_LOOPBACK)?"yes":"no";

    /* IP addresses */
    pcap_addr_t *a =d->addresses;
    for(;a!=nullptr;a=a->next) {
        Address  addresses;
        switch(a->addr->sa_family)
        {
        case AF_INET:
            addresses.saFamily = "AF_INET";
            if (a->addr)
            {
                addresses.ipAddr =  ip4tostr(a->addr);
            }
            if (a->netmask)
            {
                addresses.netmask = ip4tostr(a->netmask);
            }
            if (a->broadaddr)
            {
                addresses.netmask = ip4tostr(a->broadaddr);
            }
            if (a->dstaddr)
            {
                addresses.netmask = ip4tostr(a->dstaddr);
            }
            break;

        case AF_INET6:
            addresses.saFamily = "AF_INET6";
            if (a->addr)
            {
                addresses.ipAddr = ip6tostr(a->addr);
            }
            break;

        default:
            break;
        }
        devs->ipAddresses.append(addresses);
    }
    return devs;
}
