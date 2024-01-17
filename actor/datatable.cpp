#include "datatable.h"
#include <QHeaderView>
#include <QDebug>


DataTable::DataTable(QWidget *parent) : QTableWidget(parent)
{
    initHeader();
    m_net = SingleTon<NetMgr>::GetInstance();
}

void DataTable::initHeader()
{

    /* Header 格式设置 */
    this->horizontalHeader()->setVisible(true);
    this->setColumnCount(6);
    QStringList tableHeader;
    tableHeader << "时间" << "协议类型" << "源地址"
                << "目标地址" << "长度" << "信息";
    this->setHorizontalHeaderLabels(tableHeader);
    QFont headerFont;
    headerFont.setBold(true);
    this->horizontalHeader()->setFont(headerFont);

    /* 设置整行选中 */
    this->setSelectionBehavior ( QAbstractItemView::SelectRows);
    this->setSelectionMode(QAbstractItemView::SingleSelection);

    /* 设置不可编辑 */
    this->setEditTriggers(QAbstractItemView::NoEditTriggers);

    /* Header 自动填充表 */
    this->horizontalHeader()->setStretchLastSection(true);

    /* 自动调整列宽 */
    this->horizontalHeader()->setSectionResizeMode(SOURCE, QHeaderView::ResizeToContents);
    this->horizontalHeader()->setSectionResizeMode(DESTINATION, QHeaderView::ResizeToContents);

}


void DataTable::addData(AnsyObj ansy)
{

    QString strTime  = ansy.getData(Pro_TIME,"时间");
    QString sourceAddr;
    QString destAddr;
    QString info;
    QString strType;
    QString strl;

    if(ansy.isType(Pro_UNTODO))
    {
       return;
    }

    do
    {

        if(ansy.isType(Pro_ARP))
        {
           strType = "ARP";
           ProType t = Pro_ARP;
           sourceAddr = ansy.getData(t,"源MAC");
           destAddr= ansy.getData(t,"目标MAC");
            strl = ansy.getData(t,"len");
            if(destAddr == "00:00:00:00:00:00")
            {
                 //ARP
                 QString destIp = ansy.getData(t,"目标IP");
                 QString srcIp = ansy.getData(t,"源IP");
                 info = QString("Who has %1? Tell %2").arg(destIp).arg(srcIp);
            }
            else
            {
                 QString srcIp = ansy.getData(t,"源IP");
                 QString srcMac = ansy.getData(t,"源MAC");
                 info = QString("%1 is at %2").arg(srcIp).arg(srcMac);
            }
            break;
        }

        if(ansy.isType(Pro_IPV4))
        {

            sourceAddr = ansy.getData(Pro_IPV4,"目标IP");
            destAddr = ansy.getData(Pro_IPV4,"源IP");
            if(ansy.isType(Pro_ICMP))
            {
                strType = "ICMP";
                info = ansy.getData(Pro_ICMP,"info");
                strl = ansy.getData(Pro_ICMP,"len");
                break;
            }

            if(ansy.isType(Pro_TCP))
            {
                strType = "TCP";
                QString sp1 = ansy.getData(Pro_TCP,"源端口");
                QString sp2 = ansy.getData(Pro_TCP,"目标端口");
                info = QString("Port: %1 → Port: %2 ").arg(sp1).arg(sp2);
                strl = ansy.getData(Pro_TCP,"len");
                m_net->m_uitcp4Size += strl.toUInt();
                if(ansy.isType(Pro_HTTP))
                {
                    strType = "HTTP";
                }
                break;
            }

            if(ansy.isType(Pro_UDP))
            {
                strType = "UDP";
                QString sp1 = ansy.getData(Pro_UDP,"源端口");
                QString sp2 = ansy.getData(Pro_UDP,"目标端口");
                strl = ansy.getData(Pro_UDP,"len");
                m_net->m_uiudp4Size += strl.toUInt();
                info = QString("Port: %1 → Port: %2 ").arg(sp1).arg(sp2);
                break;
            }

            break;
        }



        if(ansy.isType(Pro_IPV6))
        {

            sourceAddr = ansy.getData(Pro_IPV6,"目标IP");
            destAddr = ansy.getData(Pro_IPV6,"源IP");
            if(ansy.isType(Pro_ICMP6))
            {
                strType = "ICMP6";
                info = ansy.getData(Pro_ICMP6,"info");
                strl = ansy.getData(Pro_ICMP6,"len");
                break;
            }

            if(ansy.isType(Pro_TCP6))
            {
                strType = "TCP6";

                QString sp1 = ansy.getData(Pro_TCP6,"源端口");
                QString sp2 = ansy.getData(Pro_TCP6,"目标端口");
                info = QString("Port: %1 → Port: %2 ").arg(sp1).arg(sp2);
                strl = ansy.getData(Pro_TCP6,"len");
                m_net->m_uitcp6Size += strl.toUInt();
                if(ansy.isType(Pro_HTTP6))
                {
                     strType = "HTTP6";
                }
                break;
            }

            if(ansy.isType(Pro_UDP6))
            {
                strType = "UDP6";
                QString sp1 = ansy.getData(Pro_UDP6,"源端口");
                QString sp2 = ansy.getData(Pro_UDP6,"目标端口");
                strl = ansy.getData(Pro_UDP6,"len");
                m_net->m_uiudp6Size += strl.toUInt();
                info = QString("Port: %1 → Port: %2 ").arg(sp1).arg(sp2);
                break;
            }
            break;
        }

    }while(false);



    int rowIndex = this->rowCount();
    this->insertRow(rowIndex);
    this->setItem(rowIndex, TIME, new QTableWidgetItem(strTime));

    this->setItem(rowIndex, PROTOCOL, new QTableWidgetItem(strType));
    this->setItem(rowIndex, SOURCE, new QTableWidgetItem(sourceAddr));
    this->setItem(rowIndex, DESTINATION, new QTableWidgetItem(destAddr));
      this->setItem(rowIndex, LENGTH, new QTableWidgetItem(strl));
    this->setItem(rowIndex, INFO, new QTableWidgetItem(info));

    /* 设置居中 */
    for(int i = 0; i < 6;i++){
        this->item(rowIndex, i)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
    }

}

void DataTable::clearTable()
{
    m_net->clearAnsy();
    this->clear();
    this->setRowCount(0);
    initHeader();
}
