#include "dlg_net.h"
#include "ui_dlg_net.h"

#include <QTreeWidgetItem>

Dlg_Net::Dlg_Net(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dlg_Net)
{
    ui->setupUi(this);
    m_pNet = SingleTon<NetMgr>::GetInstance();
    ui->treeWidget->setHeaderLabels(QStringList{"描述","内容"});
    ui->treeWidget->setColumnCount(2);
    ui->treeWidget->setColumnWidth(0,270);
}

Dlg_Net::~Dlg_Net()
{
    delete ui;
}

void Dlg_Net::showEvent(QShowEvent *event)
{
    m_vecNets.clear();
    m_vecNets = m_pNet->getNicInfo();
    ui->treeWidget->clear();

    for(const auto &it:m_vecNets)
    {
        QTreeWidgetItem *rootNic = new QTreeWidgetItem(ui->treeWidget,QStringList{"description",it.description});
        rootNic->setExpanded(true);
        /* 设备名(Name) */
        QTreeWidgetItem *devName = new QTreeWidgetItem(rootNic, QStringList(QStringList{"Name",it.name}));
        rootNic->addChild(devName);

        QTreeWidgetItem *lbAddr = new QTreeWidgetItem(rootNic, QStringList{"Loopback",it.loopbackAddr});
        rootNic->addChild(lbAddr);


        for(auto a : it.ipAddresses)
        {
            if( a.saFamily == "AF_INET")
            {
                QTreeWidgetItem *ipv4 = new QTreeWidgetItem(rootNic, QStringList{"Address Family Name: #2 ", a.saFamily});
                rootNic->addChild(ipv4);
                ipv4->setExpanded(true);
                if (!a.ipAddr.isEmpty())
                {
                    QTreeWidgetItem *ipv4Addr = new QTreeWidgetItem(ipv4, QStringList{"Address: " , a.ipAddr});
                    ipv4->addChild(ipv4Addr);
                }
                if (!a.netmask.isEmpty())
                {
                    QTreeWidgetItem *netmask = new QTreeWidgetItem(ipv4, QStringList{"Netmask: ", a.netmask});
                    ipv4->addChild(netmask);
                }
                if (!a.broadAddr.isEmpty())
                {
                    QTreeWidgetItem *broadAddr = new QTreeWidgetItem(ipv4, QStringList{"Broadcast Address: ", a.broadAddr});
                    ipv4->addChild(broadAddr);
                }
                if (!a.dstAddr.isEmpty())
                {
                    QTreeWidgetItem *dstAddr = new QTreeWidgetItem(ipv4, QStringList{"Destination Address: ", a.dstAddr});
                    ipv4->addChild(dstAddr);
                }
            }else if (a.saFamily == "AF_INET6")
            {
                QTreeWidgetItem *ipv6 = new QTreeWidgetItem(rootNic, QStringList{"Address Family Name: #23 ", a.saFamily});
                rootNic->addChild(ipv6);
                ipv6->setExpanded(true);
                if (!a.ipAddr.isEmpty())
                {
                    QTreeWidgetItem *ipv6Addr = new QTreeWidgetItem(ipv6, QStringList{"Address: ", a.ipAddr});
                    ipv6->addChild(ipv6Addr);
                }
            }else
            {
                QTreeWidgetItem *unknown = new QTreeWidgetItem(rootNic, QStringList{"Address Family Name: Unknown"});
                rootNic->addChild(unknown);
            }
        }
    }
}

void Dlg_Net::hideEvent(QHideEvent *event)
{

}

void Dlg_Net::on_pushButton_clicked()
{
    QTreeWidgetItem* curItem = ui->treeWidget->currentItem();
    while(curItem->parent()){
        curItem = curItem->parent();
    }

    auto devDesc = curItem->text(1);
    for(const auto &it:m_vecNets)
    {
        if(it.description == devDesc)
        {
            emit sendNet(it);
            this->hide();
        }
    }

}


void Dlg_Net::on_pushButton_2_clicked()
{
    this->hide();
}

