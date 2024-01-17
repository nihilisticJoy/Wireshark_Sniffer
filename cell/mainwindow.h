#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "rob/capthread.h"
#include "dlg_ansydata.h"
#include "dlg_net.h"
QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void dealData(AnsyObj);
    void updateNeter();
    void setData(QByteArray arr);
signals:
    void sendStart(DevInfo);
    void sendStop();
    void sendFilter(QString);

private slots:

    void dealDlgNetShow(DevInfo info);


    void on_btn_filter_clicked();

    void on_anction_start_triggered(bool checked);

    void on_action_clear_triggered();

    void on_action_about_triggered();

    void on_action_ansy_triggered();

private:
    CapThread *m_capThread;
    CapMgr *m_capMgr;
    Ui::MainWindow *ui;

    Dlg_Net m_dlgNet;
    Dlg_AnsyData m_dlgAnsy;
    DevInfo m_info;
    QVector<AnsyObj> m_vecDatas;

};
#endif // MAINWINDOW_H
