#ifndef DATATREE_H
#define DATATREE_H

#include <QTreeWidget>
#include <rob/capthread.h>

class DataTree:public QTreeWidget
{
     Q_OBJECT
public:
    explicit DataTree(QWidget *parent = nullptr);
    void  addPacketInfo(AnsyObj obj);
    void inittree();
};

#endif // DATATREE_H
