#ifndef CAPTHREAD_H
#define CAPTHREAD_H
#include <QThread>
#include <rob/rob.h>
#include <QMetaEnum>

#include <QTimer>


enum ProType
{
    Pro_NULL = 0,
    Pro_TIME = 1,
    Pro_MAC =  2,
    Pro_IPV4 = 3,
    Pro_IPV6 = 4,
    Pro_ARP,
    Pro_ICMP,
    Pro_ICMP6,
    Pro_TCP,
    Pro_TCP6,
    Pro_UDP,
    Pro_UDP6,
    Pro_HTTP,
    Pro_HTTP6,
    Pro_UNTODO,
};



class EnuConver:public QObject
{
    Q_OBJECT
public:

    enum ProTypeEx
    {
        DataNULL = 0,
        TIME = 1,
        MAC =  2,
        IPV4 = 3,
        IPV6 = 4,
        ARP,
        ICMP,
        ICMP6,
        TCP,
        TCP6,
        UDP,
        UDP6,
        HTTP,
        HTTP6,
        UNTODO,
    };

    Q_ENUM(ProTypeEx);

    QString get(quint32 type)
    {
         QMetaEnum enmState = QMetaEnum::fromType<ProTypeEx>();
         QString str = enmState.valueToKey(type);
         return str;
    }
};


struct  TcpPPropert
{
    ProType type;
    QString strName;
    QString strValue;

};

typedef  QList<TcpPPropert>  PList;

//属性列表
class PropertList
{

public:
    PropertList()
    {

    }
    ~PropertList()
    {

    }

    static  TcpPPropert getProperytByName(QList<TcpPPropert> &l,QString strName)
    {
        TcpPPropert t;
        for(auto it:l)
        {
            if(it.strName == strName)
            {
                    t = it;
            }
        }
        return t;
    }



    bool isEmpty()
    {
        if( m_mapProtrocl.size() == 0 && m_list.size()==0)
        {
            return true;
        }

        return false;
    }
    //清除属性
    void clear()
    {
        m_mapProtrocl.clear();
        m_list.clear();
    }


    QList<TcpPPropert>&  operator<<( TcpPPropert t)
    {
        m_list.append(t);
        return m_list;
    }



    QString getTime()
    {
        QString str;
        for(auto it :m_list)
        {
            if(it.type ==Pro_TIME && it.strName == "时间")
            {
                 str = it.strValue;
                 break;
            }
        }
        return str;
    }

    QString getData()
    {
        QString str;
        EnuConver eobj;
        for(auto it :m_list)
        {
            str = str +"["+eobj.get(it.type)+"]"+it.strName+":"+it.strValue;
        }
        return str;

    }

    QString getProType()
    {
        QString str;
        do
        {
            auto it =m_mapProtrocl.find(Pro_ARP);
            if(it !=m_mapProtrocl.end())
            {
                str = "ARP";
                break;
            }

            auto it2 =m_mapProtrocl.find(Pro_IPV4);
            if(it2 !=m_mapProtrocl.end())
            {
                str = "IPV4";
                break;
            }
        }while(false);
        return str;
    }



    QList<TcpPPropert> getList()
    {
        return m_list;
    }

    //合并属性列表
    void operator<<(PropertList l)
    {
        auto listPro =l.getList();
        for(auto it:listPro)
        {
            if(m_mapProtrocl.end() == m_mapProtrocl.find(it.type))
            {
                m_mapProtrocl.insert(it.type,PList{});
                m_list.append(it);
                continue;
            }
            m_list.append(it);
        }
    }

private:

    //所有属性
    PList m_list;

    //分类属性容器
    QMap<ProType,PList> m_mapProtrocl;
};


class AnsyObj
{

public:
    //设置分析数据
    void setData(PList l)
    {
        m_cacheType = Pro_NULL;
        m_mapProtrocl.clear();
        m_cacheList.clear();
        for(auto it:l)
        {
            auto itVec = m_mapProtrocl.find(it.type);
            if(itVec!=m_mapProtrocl.end())
            {
                itVec->append(it);
            }
            else
            {
                m_mapProtrocl.insert(it.type,PList{it});
            }
        }
    }

    //协议类型判断
    bool isType(ProType t)
    {
        if(m_mapProtrocl.find(t) == m_mapProtrocl.end())
        {
            return false;
        }
        return true;
    }

    //获取数据
    QString getData(ProType t,QString key)
    {

        QString str;
        if(t == m_cacheType)
        {
            for(auto itV :m_cacheList)
            {
                if(itV.strName ==key)
                {
                    str = itV.strValue;
                    return str;
                }
            }
        }

        auto itl = m_mapProtrocl.find(t);
        if( itl!= m_mapProtrocl.end())
        {
            m_cacheType = t;
            m_cacheList = *itl;
            for(auto itV :m_cacheList)
            {
                if(itV.strName ==key)
                {
                    str = itV.strValue;
                    break;
                }
            }
        }
        return str;
    }

     QMap<ProType,PList> getAnsyData()
     {
        return m_mapProtrocl;
     }

     void pushArr(QByteArray arr)
     {
        m_arrdara = arr;
     }

     QByteArray getArr()
     {
         return m_arrdara;
     }
private:
    QMap<ProType,PList> m_mapProtrocl;
    ProType m_cacheType;
    PList m_cacheList;
    QByteArray m_arrdara;
};


class CapThread:public QThread
{
    Q_OBJECT
public:
    void run()
    {
        qDebug()<<"Cap thread:"<<QThread::currentThreadId();
        exec();
    }
};

class AnsyObj;
class CapMgr:public QObject
{
    Q_OBJECT
public:
    CapMgr();


    //开启监听
    void dealStartCap(DevInfo info);

    //停止监视
    void dealStopCap();

    //设置过滤器
    void dealSetFilter(QString strfilter);


    //读取数据
    void readData();

    //协议解析
    void packHandler(const pcap_pkthdr *header, uchar *pkt_data);

    //MAC解析
    PropertList EtherNet_parser(quint32 pktLen,uchar *pkt_data);

    //Arp解析
    PropertList ARP_parse(uchar *pkt_data);


    //IP协议解析
    PropertList IP_parser(quint32 pktLen,uchar *pkt_data);
    PropertList IP6_parser(quint32 pktLen,uchar *pkt_data);


    //ICMP6和4差别不大,故用一个函数解析
    PropertList ICMP_parser(quint32 pktLen, uchar *pkt_data, qint32 type);

    //udp协议解析
    PropertList UDP_parser(quint32 pktLen, uchar *pkt_data, qint32 type);

    //tcp协议解析
    PropertList TCP_parser(quint32 pktLen, uchar *pkt_data, qint32 type);


signals:
    void sendRes(QString);
    void sendFilterRes(QString);
    void sendData(AnsyObj obj);

private:
    quint32 ipConvertToInt(QString ip);


    pcap_t  *m_padhandle;
    QTimer *m_ptimer;

    bool m_istart;
    QString  m_strfilter;
    DevInfo m_pnic;
};
#endif
