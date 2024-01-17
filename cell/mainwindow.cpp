#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include <rob/capthread.h>
#include <rob/netmgr.h>
#include <QDateTime>
#include <QMessageBox>
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    m_capThread = new CapThread;
    m_capThread->start();
    m_capMgr = new CapMgr;
    m_capMgr->moveToThread(m_capThread);

    qRegisterMetaType<DevInfo>("DevInfo");
    qRegisterMetaType<PropertList>("PropertList");
    qRegisterMetaType<AnsyObj>("AnsyObj");

    connect(this,&MainWindow::sendStart,m_capMgr,&CapMgr::dealStartCap);
    connect(this,&MainWindow::sendStop,m_capMgr,&CapMgr::dealStopCap);
    connect(this,&MainWindow::sendFilter,m_capMgr,&CapMgr::dealSetFilter);


    auto f =[&](QString str){
        QMessageBox::information(nullptr,"信息",str.isEmpty()?"成功":"异常"+str);
    };

    connect(m_capMgr,&CapMgr::sendRes,this,f);
    connect(m_capMgr,&CapMgr::sendFilterRes,this,f);
    connect(m_capMgr,&CapMgr::sendData,this,&MainWindow::dealData);




    auto vec = SingleTon<NetMgr>::GetInstance()->getNicInfo();
    if(vec.size()>0)
    {
      m_info = vec[0];
      updateNeter();
    }


     connect(&m_dlgNet,&Dlg_Net::sendNet,this,&MainWindow::dealDlgNetShow);

     auto fshowDlg = [&](){
        m_dlgNet.exec();
    };
     connect(ui->action_select,&QAction::triggered,this,fshowDlg);

     ui->le_net->setDisabled(true);



     connect(ui->tableWidget, &DataTable::clicked, [=](){
         auto index = ui->tableWidget->currentRow();
         if(index<m_vecDatas.size() && index>=0)
         {
             ui->treeWidget->addPacketInfo(m_vecDatas[index]);
                  setData(m_vecDatas[index].getArr());
         }

     });



}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::dealData(AnsyObj obj)
{

    m_vecDatas.append(obj);
    ui->tableWidget->addData(obj);
}




void MainWindow::dealDlgNetShow(DevInfo info)
{
    m_info = info;
}





void MainWindow::updateNeter()
{
    ui->le_net->setText("网卡"+m_info.description);
}


void MainWindow::on_btn_filter_clicked()
{
   emit  sendFilter(ui->le_filter->text());
}


void MainWindow::setData(QByteArray arr)
{
    ui->textBrowser->clear();

    QString str;
    for(int i =0;i<arr.size();i++)
    {
        str = str + QString::asprintf("%02X",static_cast<quint8>(arr[i]))+" ";
    }
    ui->textBrowser->insertPlainText(str);
}

void MainWindow::on_anction_start_triggered(bool checked)
{
    if(checked)
    {
        ui->anction_start->setIcon(QIcon(":/res/icon_stop.svg"));
        emit sendStart(m_info);
    }
    else
    {
        ui->anction_start->setIcon(QIcon(":/res/icon_start.svg"));
        emit sendStop();
    }
}


void MainWindow::on_action_clear_triggered()
{

    m_vecDatas.clear();
        ui->tableWidget->clearTable();
}


void MainWindow::on_action_about_triggered()
{
    QMessageBox::about(this,"关于软件","开发者:失落的地下城勇士 \n开发时间:2022年3月22日19:45:47");
}


void MainWindow::on_action_ansy_triggered()
{
    m_dlgAnsy.exec();
}

