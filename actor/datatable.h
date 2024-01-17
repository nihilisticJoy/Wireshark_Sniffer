#ifndef DATATABLE_H
#define DATATABLE_H

#include <QTableWidget>
#include <rob/netmgr.h>
#include <rob/capthread.h>


class DataTable : public QTableWidget
{
    Q_OBJECT
public:
    enum DataStruct{
        TIME, PROTOCOL, SOURCE, DESTINATION, LENGTH, INFO
    };

    explicit DataTable(QWidget *parent = nullptr);

    void addData(AnsyObj ansy);
    void clearTable();
private:
    void initHeader();

    NetMgr *m_net;
};

#endif // DATATABLE_H
