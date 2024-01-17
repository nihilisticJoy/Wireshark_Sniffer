#ifndef NETMGR_H
#define NETMGR_H


#include "rob.h"
#include <QObject>



class NetMgr:public QObject
{
    Q_OBJECT
public:
    friend SingleTon<NetMgr>;


    //获取网卡信息
    static QVector<DevInfo> getNicInfo();

public:
    quint64 m_uitcp4Size;
    quint64 m_uiudp4Size;
    quint64 m_uitcp6Size;
    quint64 m_uiudp6Size;

    quint64 getDataSum();
   void clearAnsy();
private:
    NetMgr();


    static DevInfo *getInfo(pcap_if_t *d);

    //ip转Sring
    static QString ip4tostr(sockaddr *addr);
    static QString ip6tostr(sockaddr *addr);
};

#endif // NETMGR_H
