#include "datatree.h"

#include <QTreeWidget>



DataTree::DataTree(QWidget *parent): QTreeWidget(parent)
{
    inittree();

}
void DataTree::inittree()
{
    this->setColumnCount(3);

    QStringList header;
    header<<"属性"<<"值"<<"说明";
    this->setHeaderLabels(header); //设置表头
    this->setStyleSheet("QTreeWidget::item{height:25px}");
}

void DataTree::addPacketInfo(AnsyObj obj)
{
    this->clear();
     QMap<ProType,PList> data =  obj.getAnsyData();

     EnuConver enumConvert;
     for(auto it = data.begin();it!=data.end();it++)
     {
         QString strType = enumConvert.get(static_cast<quint32>(it.key()));
         QTreeWidgetItem *ethernet = new QTreeWidgetItem(this, QStringList(strType));
         ethernet->setExpanded(true);
         auto &l =  it.value();
         for(int i = 0;i<l.size();i++)
         {
            QStringList lstr;
            lstr<<l.at(i).strName<<l.at(i).strValue;
            ethernet->addChild(new QTreeWidgetItem(ethernet,lstr));
         }

     }
}
