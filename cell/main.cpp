#include "mainwindow.h"

#include <QApplication>


int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

#if 0 //测试函数入口，1开 0关
    SingleTon<Tester>::GetInstance()->test_Main();
#endif
    MainWindow w;
    w.show();
    return a.exec();
}
