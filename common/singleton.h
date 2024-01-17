#ifndef SINGLETON_H
#define SINGLETON_H

#include <mutex>
using namespace  std;
//单例模板
template <typename T>
class SingleTon
{
public:
    static T *GetInstance()
    {
        if(nullptr == pSingle)
        {
            lock_guard<mutex> lock(mtx);
            if(nullptr == pSingle)
            {
                pSingle = new T();
            }
        }
        return pSingle;
    }
private:
    SingleTon()
    {

    }

    ~SingleTon()
    {
        if(nullptr !=pSingle)
        {
            delete  pSingle;
            pSingle = nullptr;
        }
    }

    static T *pSingle;
    static mutex mtx;
};

template  <typename T>
mutex SingleTon<T>::mtx;

template  <typename T>
T* SingleTon<T>::pSingle =nullptr;
#endif // SINGLETON_H
