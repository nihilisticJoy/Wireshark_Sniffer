QT       += core gui


greaterThan(QT_MAJOR_VERSION, 4): QT += widgets printsupport
CONFIG += c++11

# The following define makes your compiler emit warnings if you use
# any Qt feature that has been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0



# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

HEADERS += \
    actor/datatable.h \
    actor/datatree.h \
    cell/dlg_ansydata.h \
    cell/dlg_net.h \
    cell/mainwindow.h \
    common/singleton.h \
    qcustomplot/qcustomplot.h \
    rob/capthread.h \
    rob/netmgr.h \
    rob/rob.h

SOURCES += \
    actor/datatable.cpp \
    actor/datatree.cpp \
    cell/dlg_ansydata.cpp \
    cell/dlg_net.cpp \
    cell/main.cpp \
    cell/mainwindow.cpp \
    qcustomplot/qcustomplot.cpp \
    rob/capthread.cpp \
    rob/netmgr.cpp

FORMS += \
    cell/dlg_ansydata.ui \
    cell/dlg_net.ui \
    cell/mainwindow.ui


DESTDIR += $$PWD/bin
unix:!macx{
LIBS += -lpcap
}



win32 {
 LIBS += -L$$PWD/npacp-sdk-1.12/Lib/x64/ -lPacket
 LIBS += -L$$PWD/npacp-sdk-1.12/Lib/x64/ -lwpcap
 LIBS += -lws2_32
 INCLUDEPATH += $$PWD/npacp-sdk-1.12/Include
}

RESOURCES += \
    res.qrc


DESTDIR = $$PWD/bin/
