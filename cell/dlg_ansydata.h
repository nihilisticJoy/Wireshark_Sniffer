#ifndef DLG_ANSYDATA_H
#define DLG_ANSYDATA_H

#include <QDialog>
#include <QTimer>
#include <rob/netmgr.h>
#include "qcustomplot/qcustomplot.h"
namespace Ui {
class Dlg_AnsyData;
}

class Dlg_AnsyData : public QDialog
{
    Q_OBJECT

public:
    explicit Dlg_AnsyData(QWidget *parent = nullptr);
    ~Dlg_AnsyData();


    virtual void showEvent(QShowEvent *event);
    virtual void hideEvent(QHideEvent *event);

    void drawPlot();

private:
    Ui::Dlg_AnsyData *ui;
    QTimer m_timer;
    NetMgr    *m_pNet ;

    QCPBars *m_bar;
};

#endif // DLG_ANSYDATA_H
