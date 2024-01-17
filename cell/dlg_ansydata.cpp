#include "dlg_ansydata.h"
#include "ui_dlg_ansydata.h"

Dlg_AnsyData::Dlg_AnsyData(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dlg_AnsyData)
{
    ui->setupUi(this);
    m_pNet = SingleTon<NetMgr>::GetInstance();


    //柱状图对象
    m_bar = new QCPBars(ui->plot->xAxis, ui->plot->yAxis);

    // prepare x axis with country labels:
    QVector<double> ticks;
    QVector<QString> labels;
    ticks << 1 << 2 << 3 << 4;

    labels << "tcp4" << "tcp6" << "udp4" << "udp6";
    QSharedPointer<QCPAxisTickerText> textTicker(new QCPAxisTickerText);
    textTicker->addTicks(ticks, labels);

    ui->plot->xAxis->setTicker(textTicker);
    ui->plot->xAxis->setSubTicks(false);
    ui->plot->xAxis->setTickLength(0, 4);
    ui->plot->xAxis->setRange(0, 5);
    ui->plot->xAxis->setBasePen(QPen(Qt::black));
    ui->plot->xAxis->setTickPen(QPen(Qt::black));
    ui->plot->xAxis->setTickLabelColor(Qt::black);
    ui->plot->xAxis->setLabelColor(Qt::black);

    // prepare y axis:
     ui->plot->yAxis->setRange(0, 12.1);

     ui->plot->yAxis->setPadding(5);
     ui->plot->yAxis->setTickLabelRotation(90);
     ui->plot->yAxis->setLabel("流量统计");
     ui->plot->yAxis->setBasePen(QPen(Qt::black));
     ui->plot->yAxis->setTickPen(QPen(Qt::black));
     ui->plot->yAxis->setSubTickPen(QPen(Qt::black));
     ui->plot->yAxis->setTickLabelColor(Qt::black);
     ui->plot->yAxis->setLabelColor(Qt::black);





    ui->plot->setInteractions(QCP::iRangeDrag | QCP::iRangeZoom);

    connect(&m_timer,&QTimer::timeout,this,&Dlg_AnsyData::drawPlot);
}



Dlg_AnsyData::~Dlg_AnsyData()
{
    delete ui;
}

void Dlg_AnsyData::showEvent(QShowEvent *event)
{
    m_timer.start(1000);
}

void Dlg_AnsyData::hideEvent(QHideEvent *event)
{
    m_timer.stop();
}

void Dlg_AnsyData::drawPlot()
{

    //更新y轴
    auto max = m_pNet->getDataSum();
    ui->plot->yAxis->setRange(0, max);

    //设置y轴取值范围

    //更新值
     QVector<double> ticks;
     QVector<QString> labels;

     ticks << 1 << 2 << 3 << 4;
     labels << "tcp4\n"+QString::number(m_pNet->m_uitcp4Size)+"字节"
            << "tcp6\n"+QString::number(m_pNet->m_uitcp6Size)+"字节"
            << "udp4\n"+QString::number(m_pNet->m_uiudp4Size)+"字节"
            << "udp6\n"+QString::number(m_pNet->m_uiudp6Size)+"字节";
     QSharedPointer<QCPAxisTickerText> textTicker(new QCPAxisTickerText);
     textTicker->addTicks(ticks, labels);


    QVector<double> v;
    v << m_pNet->m_uitcp4Size << m_pNet->m_uitcp6Size <<m_pNet->m_uiudp4Size << m_pNet->m_uiudp6Size;
    m_bar->setData(ticks, v);

    ui->lb_tcp4->setText(QString::number(m_pNet->m_uitcp4Size));
    ui->lb_tcp6->setText(QString::number(m_pNet->m_uitcp6Size));
    ui->lb_udp4->setText(QString::number(m_pNet->m_uiudp4Size));
    ui->lb_udp6->setText(QString::number(m_pNet->m_uiudp6Size));
    ui->plot->update();
}
