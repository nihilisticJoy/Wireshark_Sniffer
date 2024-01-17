#ifndef DLG_NET_H
#define DLG_NET_H

#include <QDialog>

#include <rob/netmgr.h>

namespace Ui {
class Dlg_Net;
}

class Dlg_Net : public QDialog
{
    Q_OBJECT

public:
    explicit Dlg_Net(QWidget *parent = nullptr);
    ~Dlg_Net();

    virtual void showEvent(QShowEvent *event);
    virtual void hideEvent(QHideEvent *event);
signals:
    void sendNet(DevInfo);
private slots:
    void on_pushButton_clicked();

    void on_pushButton_2_clicked();

private:
    Ui::Dlg_Net *ui;
    NetMgr    *m_pNet ;
    QVector<DevInfo> m_vecNets;
};

#endif // DLG_NET_H
