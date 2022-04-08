#include <windows.h>
#include <stdio.h>
#include <Psapi.h>
 
class TestVMT//Простой класс с использованием VMT
{
public:
 
virtual void Func1();
virtual void Func2();
virtual void Func3();
virtual void Func4();
virtual void Func5();
 
DWORD64 ad = 0;
 
};
 
void TestVMT::Func1()
{
MessageBoxA(0, "Func1", 0, 0);
}
 
void TestVMT::Func2()
{
MessageBoxA(0, "Func2", 0, 0);
}
 
void TestVMT::Func3()
{
MessageBoxA(0, "Func3", 0, 0);
}
 
void TestVMT::Func4()
{
MessageBoxA(0, "Func4", 0, 0);
}
 
void TestVMT::Func5()
{
MessageBoxA(0, "Func5", 0, 0);
}
 
typedef int (WINAPI* MessageBoxS)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);// Прототип функции
MessageBoxS box = (MessageBoxS)0x7FFFB8B88120;// Адресс взят напрямую чтоб не заморачиваться
 
 
void hookfunc()//функция которая будет выполняться вместо  оригинала
{
box(0, 0, 0, 0);
}
 
LPVOID Hook(LPVOID pClass, LPVOID pHookFunc, int dwOffset)// Функция которая устанавливает хук в виртуальной таблице методов (VMT)
{
LPVOID pVTable = *(LPVOID*)pClass;//Получаем адресс vmt таблица всегда находится по нулевому смещению
LPVOID pAdressInTable = (LPVOID)((DWORD64)pVTable + dwOffset * 8);//Вычисляем адресс функции в таблице по ее порядковому номеру
 
 
DWORD dwOldProtection;
VirtualProtect((LPVOID)pAdressInTable, sizeof(pAdressInTable), PAGE_READWRITE, &dwOldProtection);// меняем параметры страницы установка флага чтение запись
 
memcpy(pAdressInTable, pHookFunc, 8);//Записываем наш адресс хука
 
VirtualProtect((LPVOID)pAdressInTable, sizeof(pAdressInTable), dwOldProtection, &dwOldProtection);// Восстановили параметры страницы
 
return (LPVOID)pAdressInTable;// Вернули адресс из таблицы где установили хук
}
 
bool DetectVMT(LPVOID pClass, int MaxCount)// Простая функция для детекта хука. Проверяет таблицу VMT на изменения адрессов функций
{
DWORD64 pVMT = *(DWORD64*)pClass;//Получаем адресс vmt таблица всегда находится по нулевому смещению
 
MODULEINFO mInfo;// Структура которая будет получать информацию о модуле (конкретно наша программа)
 
GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(0), &mInfo, sizeof(mInfo));// Можете в гугл заглянуть что делает эта функция
printf("Base adress %llp\n", mInfo.lpBaseOfDll);
 
DWORD64 EndFile = (DWORD64)mInfo.lpBaseOfDll + mInfo.SizeOfImage;// Вычисляем конец нашей программы базовый адресс + размер. Нужен для сравнения адрессов. Так как в основном адресса которые в таблице VMT не могут быть за пределами пространства программы
 
for (int i = 0; i < MaxCount; i++)// Перебор таблицы методов
{
printf("VMT check %llp\n", *(DWORD64*)pVMT);
if(*(DWORD64*)pVMT > EndFile)return 1;// Если адресс функции в таблице больше адресного пространства нашей программы то детект(Тоесть адресс ссылается на внешний код за пределами проги)
if (*(DWORD64*)pVMT < (DWORD64)mInfo.lpBaseOfDll)return 1;// Если адресс функции в таблице меньше (для тех кто выделил память ниже нашей проги)
 
pVMT += 8;//К первому адрессу в таблице прибавляем 8 байт это размер адрессов в х64 системе. Тем самым переходим на след функцию в таблице
}
 
 
return 0;// 0 если все адресса находятся в рамках пространства программы
}
 
 
int main()
{
TestVMT* pTestVMT = new TestVMT;
 
printf("class adr %llp\n", pTestVMT);
 
pTestVMT->Func4();// Проверка функции до хука
 
if(DetectVMT(pTestVMT, 5))printf("VMT Detect hook\n");//Проверка таблицы перед хуком
else
{
printf("VMT UNDetect hook\n");
}
 
system("pause");
 
LPVOID vAdress = VirtualAlloc(0, 100, MEM_COMMIT, PAGE_EXECUTE_READWRITE);// Выделяем память для хука (Имитируем что мы заинжектили чит)
memcpy(vAdress, (LPVOID)hookfunc, 100);// Запись кода hookfunc
printf("vAdress %llp\n", vAdress);
 
system("pause");
 
LPVOID adresshook = Hook(pTestVMT, &vAdress, 3);// Установка хука в VMT (1 класс 2 адресс хука 3 номер функции в таблице)
printf("adresshook %llp\n", adresshook);
system("pause");
 
pTestVMT->Func4();// Повторно вызывает функцию после хука для проверки
 
if (DetectVMT(pTestVMT, 5))printf("VMT Detect hook\n");// Повторно проверяем наше таблицу VMT класса
else
{
printf("VMT UNDetect hook\n");
}
 
system("pause");
 
return 1;
}
