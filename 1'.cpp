#include <stdio.h> 
#define INITGUID 
#include <Windows.h> 
#include <GPEdit.h> 
int main(int argc, char* argv[]) 
{ 
if (argc == 1) 
return 0; 
// инициализируем com-библиотеки 
HRESULT hr = CoInitializeEx(NULL,//зарезервирован 
COINIT_APARTMENTTHREADED);//используем раздельное адресное пространство потоков, т.к. IGroupPolicy не поддерживает многопоточный праллелизм объектов 


IGroupPolicyObject *p = NULL;//интерфейс предоставляет методы для создания и изменения объекта групповой политики 
//наследуется от интерфейса IUnknown. 

// Создаем com-объект (обьект политики), т.е. запрашиваем нужный интерфейс 
hr = CoCreateInstance(CLSID_GroupPolicyObject,//идентификатор класса 
NULL, 
CLSCTX_INPROC_SERVER, //контекст для хранилища сервера 
IID_IGroupPolicyObject,//ссылка на IID для заданного интерфейса, который необходимо возвратить из созданного компонентного объекта 
(void**)&p);//указатель на возвращаемый интерфейс 

if (p == NULL) 
{ 
printf("Failed to get IGroupPolicyObject\n"); 
return 1; 
} 

// Читаем локальную GPO 
hr = p->OpenLocalMachineGPO(GPO_OPEN_LOAD_REGISTRY);// открыть объект локальной политики безопасности и прочитать файлы Registry.pol 
if (hr != S_OK) 
{ 
printf("Failed to open local machine GPO\n"); 
return 1; 
} 

HKEY hkey = 0; 

// получаем описатель открываемого реестра 
hr = p->GetRegistryKey(GPO_SECTION_USER, &hkey); 
// Открываем нужный ключ 
HKEY k1; 
RegOpenKey(hkey, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", &k1); 

int data = 0; 
// Что делаем - включаем или отключаем? 
if (strcmp(argv[1], "-r") == 0) 
data = 0; 
else 
data = 1; 

// Пишем значение 
RegSetValueEx(k1, L"DisallowRun", 0, REG_DWORD, (BYTE*)&data, sizeof(data)); 

RegCloseKey(k1); 
// Если включаем - то открываем файл и пролистываем его 
if (data == 1) 
{ 
//создаем раздел в реестре, либо открываем если уже существует 
RegCreateKey(hkey, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun", &k1); 

wchar_t wbuf[100],wname[100]; 
char buf[100]; 
FILE *f = fopen(argv[1], "r"); 
// Что-то файла нету 
if (f == NULL) 
{ 
printf("Failed to open %s\n", buf); 
return 1; 
} 

int i = 1; 

while (!feof(f)) 
{ 
if (fgets(buf, 100, f) == NULL) break; 

// Обрезаем перенос в конце (и вообще все лишнее) 
int p = strlen(buf) - 1; 

while ((p > 0) & (buf[p] <= ' ')) 
{ 
buf[p] = 0; 
p--; 
} 
if (strlen(buf) == 0) continue; 


// Пишем значение 
swprintf(wbuf, L"%d", i); 
mbstowcs(wname, buf, 100); 
RegSetValueEx(k1, //дескриптор ключа 
wbuf,//адрес устанавливаемого значение 
0, //зарезервированно 
REG_SZ, //тип данных 
(BYTE*)wname,//данные 
(wcslen(wname) + 1) * 2);//размер данных 

i++; 
} 
RegCloseKey(k1); 
} 
if (data == 0) { 
RegDeleteKey(hkey, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun"); 
} 
// {DD0E8ACC-03F9-4076-B2B5-0D1E140D5C40} 
GUID thisTool = 
{ 0xdd0e8acc, 0x3f9, 0x4076,{ 0xb2, 0xb5, 0xd, 0x1e, 0x14, 0xd, 0x5c, 0x40 } }; 
GUID regExt = REGISTRY_EXTENSION_GUID; 

RegCloseKey(hkey); 

// Сохраняем правки 
// указать что настройки локальной политики изменились 
hr = p->Save(FALSE, //сохраняем параметры политики пользователя, если true - токомпьютера 
TRUE,//операция добавления, если false то параметр политики удаляется длся regExt 
&regExt, //указывает что локальная политика была изменена через изменение Registry.pol файлов 
&thisTool);//новый GUID 
//закрываем интерфейс 
hr = p->Release(); 


return 0; 
}