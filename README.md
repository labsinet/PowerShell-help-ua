![Image alt](./Logo/PowerShell-Commands.png)


- [Help](#help)
- [Object](#object)
- [npp](#npp)
- [Regex](#regex)
- [DataType](#datatype)
- [Bit](#bit)
- [Files](#files)
- [Credential](#credential)
- [WinEvent](#winevent)
- [Firewall](#firewall)
- [Defender](#defender)
- [WindowsUpdate](#windowsupdate)
- [DISM](#dism)
- [Scheduled](#scheduled)
- [Network](#network)
- [RDP](#rdp)
- [Shutdown](#shutdown)
- [LocalAccounts](#localaccounts)
- [SMB](#smb)
- [ActiveDirectory](#activedirectory)
- [repadmin](#repadmin)
- [dcdiag](#dcdiag)
- [ntdsutil](#ntdsutil)
- [GPO](#gpo)
- [ServerManager](#servermanager)
- [DNS](#dnsserver)
- [DHCP](#dhcpserver)
- [DFS](#dfs)
- [StorageReplica](#storagereplica)
- [PS2EXE](#ps2exe)
- [NSSM](#nssm)
- [Jobs](#jobs)
- [SMTP](#smtp)
- [Hyper-V](#hyper-v)
- [VMWare/PowerCLI](#vmwarepowercli)
- [Exchange/EMShell](#exchangeemshell)
- [TrueNAS](#truenas)
- [Veeam](#veeam)
- [REST API](#rest-api)
- [Pode](#pode)
- [Selenium](#selenium)
- [IE](#ie)
- [COM](#com)
- [dotNET](#dotnet)
- [Console API](#console-api)
- [Drawing](#drawing)
- [ObjectEvent](#objectvent)
- [Sockets](#sockets)
- [Excel](#excel)
- [CSV](#csv)
- [XML](#xml)
- [JSON](#json)
- [YAML](#yaml)
- [HTML](#html)
- [SQLite](#sqlite)
- [MySQL](#mysql)
- [MSSQL](#mssql)
- [InfluxDB](#influxdb)
- [Telegraf](#telegraf)
- [Elasticsearch](#elasticsearch)
- [CData](#cdata)
- [ODBC](#odbc)
- [PostgreSQL](#postgresql)
- [WMI](#wmi)
- [Regedit](#regedit)
- [Performance](#performance)
- [SNMP](#snmp)
- [Zabbix](#zabbix)
- [pki](#pki)
- [OpenSSL](#openssl)
- [OpenVPN](#openvpn)
- [Route](#route)
- [NAT](#nat)
- [WireGuard](#wireguard)
- [VpnClient](#vpnclient)
- [Proxy](#proxy)
- [OpenSSH](#openssh)
- [WinRM](#winrm)
- [PackageManagement](#packagemanagement)
- [NuGet](#nuget)
- [Git](#git)
- [DSC](#dsc)
- [Ansible](#ansible)
- [GigaChat](#GigaChat)
- [YandexGPT](#YandexGPT)
- [SuperAGI](#superagi)
- [Replicate](#replicate)
- [Google-API](#google-api)
- [RapidAPI](#rapidapi)
- [TMDB](#tmdb)
- [ivi] (#ivi)
- [Kinopoisk](#kinopoisk)
- [VideoCDN](#videocdn)
- [Telegram](#telegram)
- [Discord](#discord)
- [oh-my-posh](#oh-my-posh)
- [Pester](#pester)

# Help

`Get-Verb` дії/дієслова, затверджені для використання в командах \
`Get-Command *Language*` шукати команди за іменами \
`(Get-Command Get-Language).Module` дізнатися, до якого модуля належить команда \
`Get-Command Get-Content | fl Module,DLL` дізнатися належність команди до модуля і dll \
`Get-Command -Module LanguagePackManagement` відобразити список команд вказаного модуля \
`(Get-Module LanguagePackManagement).ExportedCommands.Values` відобразити список команд зазначеного модуля \
Get-Language | Get-Member` відображає список методів команд (дій), об'єктів виведення та Event (об'єктів події: Click) \
`(Get-Help Get-Service). Aliases` дізнатися псевдонім команди \
`Get-Alias gsv` дізнатися ім'я команди за псевдонімом \
`Get-Help Get-Service` синтаксис \
`Get-Help Get-Service -Parameter *` опис всіх параметрів \
`Get-Help Get-Service-Online` \
`Get-Help Get-Service -ShowWindow` опис параметрів у GUI з фільтрацією \
`Show-Command` вивести список команд у GUI \
`Show-Command Get-Service` список команд у параметрах GUI \
`Invoke-Expression` iex приймає текст для виконання в консолі як команда \
`$PSVersionTable` версія PowerShell \
`Set-ExecutionPolicy Unrestricted` \
`Get-ExecutionPolicy` \
`$Metadata = New-Object System.Management.Automation.CommandMetaData (Get-Command Get-Service)` отримати інформацію про команду \
`[System.Management.Automation.ProxyCommand]::Create($Metadata)` вихідний код функції

# Object

### Variable

`$var = Read-Host "Enter"` ручний ввід \
`$pass = Read-Host "Введіть пароль" -AsSecureString` приховувати набір \
`$global:path = "\\path"` задати глобальну змінну, наприклад у функції \
`$using:srv` використовувати змінну текучу сесію в Invoke-сесії \
`Get-Variable` відобразити всі змінні \
`ls змінна:/` відобразити всі змінні \
`Get-Variable *srv*` знайти змінну за іменем \
`Get-Variable -Scope Global` відобразити всі глобальні змінні \
`Get-Variable Error` остання команда з помилкою \
`Remove-Variable -Name *` очистити всі змінні \
`$LASTEXITCODE` містить код виведення останньої запущеної програми, наприклад ping. Якщо код повертається позитивно (True), $LastExitCode = 0

### ENV

`Get-ChildItem Env:` відобразити всі змінні оточення \
`$env:PSModulePath` директорії імпорту модулів \
`$env:userprofile` \
`$env:computername` \
`$env:username` \
`$env:userdnsdomain` \
`$env:logonserver` \
`([DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).Name` \
`[Environment]::GetFolderPath('ApplicationData')`

### History

`Get-History` історія команди поточної сесії \
`(Get-History)[-1].Duration.TotalSeconds` час виконання останньої команди \
`(Get-PSReadLineOption).HistorySavePath` шлях до збереженого файлу з 4096 останніми командами (з модуля PSReadLine) \
`Get-Content (Get-PSReadlineOption).HistorySavePath | Select-String Отримати пошук за вмістом файлу (GREP) \
`Set-PSReadlineOption -MaximumHistoryCount 10000` змінити кількість збережених команд у файлі \
`Get-PSReadLineOption | виберіть MaximumHistoryCount`\
`Set-PSReadlineOption -HistorySaveStyle SaveNothing` відключити ведення журналу \
`F2` переключитися з InlineView на ListView

### Clipboard

`Set-Clipboard $srv` скопіювати в буфер обміну \
`Get-Clipboard` вставити

### Write

`Write-Host -ForegroundColor Black -BackgroundColor Green "Test" -NoNewline` \
`Write-Error Test` \
`Foreach ($n in 1..100) {Write-Progress -Activity "Test Progress" -PercentComplete $n}`

### Array

`$srv = @("сервер-01", "сервер-02")` створити масив \
`$srv += @("server-03")` додати до масиву новий елемент \
`$srv.Count` відобразити кількість елементів у масиві \
`Out-String` постстроковий висновок

### Index

`$srv[0]` вивести перше значення елемента масиву \
`$srv[0] = Ім'я` заміна елемента в масиві \
`$srv[0].Length` визначити кількість символів першого значення в масиві \
`$srv[10..100]` зріз
```PowerShell
$масив = "a", "b", "c", "d"
$num = 0
foreach ($a в $array) {
$num += 1
$index = [array]::IndexOf($array, $a) # дізнатися номер індексу за вказанням
$array[$index] = $num # перебрати вихідний масив
}
````
### HashTable
```PowerShell
$hashtable = @{"Користувач" = "$env:ім'я користувача"; "Server" = "$env:computername"} # створити
$hashtable += @{"User2" = "$env:username"; "Server2" = "$env:computername"} # додати ключі
$hashtable.Keys # список усіх ключів
$hashtable["User"] # отримати значення (Values) за ключом
$hashtable["User"] = "Тест" # змінити
$hashtable.Remove("Користувач") # видалити ключ
````
`$Tag = @{$true = 'dev'; $false = 'prod'}[([System.Net.Dns]::GetHostEntry("localhost").HostName) -match '.*.TestDomain$']`

### Collections/List
```PowerShell
$Collections = New-Object System.Collections.Generic.List[System.Object]
$Collections.Add([PSCustomObject]@{User = $env:username; Server = $env:computername})
````
### PSCustomObject
```PowerShell
$CustomObject = [PSCustomObject][ordered]@{User = $env:username; Server = $env:computername}
$CustomObject | Add-Member –MemberType NoteProperty –Name Arr –Value @(1,2,3) # додати Property (властивість/стобець)
$CustomObject.Arr = @(1,3,5) # змінити вміст
$CustomObject.PsObject.Properties.Remove('User') # видалити Property
````
### Add-Member
```PowerShell
$ScriptBlock = {Get-Service}
$CustomObject | Add-Member -Name TestMethod -MemberType ScriptMethod -Value $ScriptBlock # Додати Method
$CustomObject | Get-Member
$CustomObject.TestMethod()
````
### Class
```PowerShell
Class CustomClass {
[string]$User
[string]$Server
Start([bool]$Param1) {
If ($Param1) {Write-Host "Start Function"}}
}

$Class = New-Object -TypeName CustomClass
$Class.User = $env:username
$Class.Server = $env:computername
$Class.Start(1)
````
### Pipeline

$obj | Add-Member -MemberType NoteProperty -Name "Type" -Value "user" -Force` додавання об'єкта виведення NoteProperty \
$obj | Add-Member -MemberType NoteProperty -Name "User" -Value "admin" -Force` зміна вмісту для сутності об'єкта User \
`ping $ srv | Out-Null` перенаправити результат виведення в Out-Null

### Select-Object

Get-Process | Select-Object -Property *` відобразити всі доступні об'єкти виведення \
Get-Process | select -Unique "Name"` видалити значення, що повторюються в масиві \
Get-Process | select -ExpandProperty ProcessName` перетворити з об'єкта-колекції на масив (вивести вміст без найменування стовпця) \
`(Get-Process | ? Name -match iperf).Modules` список використовуваних модулів процесом

### Expression
```PowerShell
ps | Sort-Object -Descending CPU | select -first 10 ProcessName, # сортування за CPU, вивести перших 10 значень (-first)
@{Name="ProcessorTime"; Expression={$_.TotalProcessorTime -replace "\.\d+$"}}, # витрачено процесорного часу в хвилинах
@{Name="Memory"; Expression={[string]([int]($_.WS / 1024kb))+"MB"}}, # ділимо байти на КБ
@{Label="RunTime"; Expression={((Get-Date) - $_.StartTime) -replace "\.\d+$"}} # відняти з поточного часу - час запуску, і видалити milisec
````
### Select-String

`$(ipconfig | Select-String IPv4) -replace ".+:" | Where-Object {$_ -match "^172."}` дізнатися тільки IP \
`$Current_IP = Get-Content $RDCMan_RDG_PATH | Select-String $RDCMan_Display_Name -Context 0,1` отримати два рядки \
`$Current_IP = $Current_IP.Context.DisplayPostContext[0] -replace ".+<name>|<\/name>"` забрати тільки другий рядок і видалити теги

### Format-Table/Format-List

Get-Process | ft ProcessName, StartTime -Autosize` автоматичне угруповання розміру стовпців

### Measure-Object

Get-Process | Measure | select Count` у об'єктів \
Get-Process | Measure -Line -Word -Character` у рядків, слів та Char об'єктів \
Get-Process | Measure-Object PM-sum | Select-Object Count,@{Name="MEM_MB"; Expression={[int]($_.Sum/1mb)}}` кількість процесів і загальний обсяг зайнятої пам'яті в МБайт

### Compare-Object

`Compare-Object -ReferenceObject (Get-Content -Path .\file1.txt) -DifferenceObject (Get-Content -Path .\file2.txt)` порівняння двох файлів \
`$group1 = Get-ADGroupMember -Identity "Domain Admins"` \
`$group2 = Get-ADGroupMember -Identity "Enterprise Admins"` \
`Compare-Object -ReferenceObject $group1 -DifferenceObject $group2 -IncludeEqual`
`==` немає змін \
`<=` є зміни в $group1 \
`=>` є зміни в $group2

### Where-Object (?)

Get-Process | Where-Object {$_.ProcessName -match "zabbix"}` фільтрація/пошук процесів на ім'я властивості об'єкта \
Get-Process | де CPU -gt 10 | Sort-Object -Descending CPU` вивести об'єкти, де значення CPU більше 10 \
Get-Process | where WS -gt 200MB` відобразити процеси де WS вище 200МБ \
Get-Service | where Name -match "zabbix"` пошук служби \
`Get-Service -ComputerName $srv | Where {$_.Name -match "WinRM"} | Restart-Service` перезапустити службу на віддаленому комп'ютері \
`(Get-Service).DisplayName` вивести значення властивості масиву \
netstat -an | where {$_ -match 443}`\
netstat -an | ?{$_ -match 443}`\
`(netstat-an)-match 443`

### Sort-Object

Get-Process | Sort-Object -Descending CPU | ft` зворотне (-Descending) сортування по CPU \
`$path[-1..-10]` зворотне складання масиву без сортування

### Last/First

Get-Process | Sort-Object -Descending CPU | select -First 10` вивести перших 10 об'єктів \
Get-Process | Sort-Object -Descending CPU | select -Last 10` вивести останніх 10 об'єктів

### Group-Object
```PowerShell
$Groups = Get-CimInstance -Class Win32_PnPSignedDriver |
Select-Object DriverProviderName, FriendlyName, Description, DriverVersion, DriverDate |
Group-Object DriverProviderName, FriendlyName, Description, DriverVersion, DriverDate
$(foreach ($Group in $Groups) {
$Group.Group[0]
}) | Format-Table
````
# npp

`pwsh -NoExit -ExecutionPolicy Unrestricted -WindowStyle Maximized -File "$(FULL_CURRENT_PATH)"'

`%AppData%\Notepad++` themes/shortcuts.xml
````
<?xml version="1.0" encoding="UTF-8" ?>
<NotepadPlus>
<InternalCommands />
<Macros>
<Macro name="`+\+&gt;" Ctrl="yes" Alt="no" Shift="no" Key="190">
<Action type="0" message="2453" wParam="0" lParam="0" sParam="" />
<Action type="1" message="2170" wParam="0" lParam="0" sParam="`" />
<Action type="0" message="2451" wParam="0" lParam="0" sParam="" />
<Action type="0" message="2451" wParam="0" lParam="0" sParam="" />
<Action type="1" message="2170" wParam="0" lParam="0" sParam=" " />
<Action type="1" message="2170" wParam="0" lParam="0" sParam="\" />
<Action type="0" message="2300" wParam="0" lParam="0" sParam="" />
</Macro>
</Macros>
<UserDefinedCommands>
<Command name="PowerShell7" Ctrl="no" Alt="yes" Shift="no" Key="116">pwsh -NoExit -ExecutionPolicy Unrestricted -WindowStyle Maximized -File &quot;$(FULL_CURRENT_PATH)&quot;</Command >
</UserDefinedCommands>
<PluginCommands />
<ScintillaKeys />
</NotepadPlus>
````
`Parsing text to Markdown:` \
`Macros: FnLeft+'+FnRight+FnRight+\s\\Down` \
`Replace: "#","'"`
````
. 		# Позначає будь-який символ
\ 		# Екрануючий символ. Символи які екрануються: ^, [, ., $, {, *, (, ), \, +, |, ?, <, >
^ 		# Початок рядка
$ 		# Кінець рядка
\n 		# Новий рядок
\d 		# Будь-яка цифра
\D 		# Не цифра
\w 		# Будь-яка буква латиниці, цифра, або знак підкреслення
\W 		# Не латиниця, не цифра, не підкреслення
\s 		# Пробіл, табуляція, перенесення рядка
\S 		# Не пробіл
\b 		# Кордон слова. Застосовується коли потрібно виділити, що символи є словом, а не частиною іншого слова
\B 		# Не межа слова
\< 		# Початок слова
\> 		# Кінець слова
\A 		# Початок тексту
\Z 		# Кінець тексту
* 		# Повторювач. Попередній символ може працювати 0 і більше разів.
+ 		# Кількість попереднього не менше одного.
? 		# Обмежувач. Не більше одного разу
| 		# Або. Поєднує кілька варіантів
() 		# У круглі дужки полягають всі комбінації з "або" і пошук початку і кінця рядків
[ ] 	# У квадратних дужках задаються символи для пошуку, наприклад [a-яА-Я], або [0-9]
[^] 	# Виключає з пошуку символи вказані у квадратних дужках
{ } 		# У фігурних дужках вказується точна кількість входжень
\d{2} 	# Знайти дві цифри
\d{2,4} 	# Знайти дві чи чотири
{4,} 	# Знайти чотири і більше

^\s{1,}#.+` пошук спочатку рядка коментаря та пробіл після нього 1 або більше і будь-яка кількість символів
````
# Regex

`-replace "1","2"` заміна елементів в індексах масиву (скрізь де є 1, замінити на 2), для видалення використовується тільки перше значення \
`-split " "` перетворити рядок на масив, роздільником зазначений пробіл, який видаляється ($url.Split("/")[-1]) \
`-join " "` перетворити масив (колекцію) в єдиний рядок (string), додати роздільником пробіл \

`-like *txt*` пошук по масках wildcard, виводить значення на екран \
`-match txt` пошуку за шаблонами, перевірка на відповідність вмісту тексту \
`-match "zabbix|rpc"` умови, для пошуку за кількома словами \
`-NotMatch` перевірка на відсутність входження \

### Matches

`$ip = "192.168.10.1"` \
`$ip -match "(\.\d{1,3})\.\d{1,2}"`True \
`$Matches` відобразити всі відповідні змінні останнього пошуку, які входять до групи ()

`$String = "09/14/2017 12:00:27 - mtbill_post_201709141058.txt 7577_Delivered: OK"` \
`$String -Match ".*(?=\.txt)" | Out-Null`\
`$Matches[0][-4..-1] -Join ""`

`$string.Substring($string.IndexOf(".txt")-4, 4)` 2-й варіант (IndexOf)`

### Форматування (.NET method format)

`[string]::Format("{1} {0}","Index0","Index1")` \
`"{1} {0}" -f "Index0", "Index1"` \
`"{0:###-##-##}" -f 1234567` записати число в іншому форматі (#) \
`"{0:0000}" -f 123` вивести число у форматі не менше 4 знаків (0123) \
`"{0:P0}" -f (220/1000)` порахувати у відсотках (P) \
``{0:P}" -f (512MB/1GB)` скільки % становить 512Мб від 1Гб \
"{0:0.0%}" -f 0.123` помножити на 100%
```PowerShell
$ gp = Get-Process | sort cpu -Descending | select -First 10
foreach ($p in $gp) {
"{0} - {1:N2}" -f $p.processname, $p.cpu # округлити
}
````
### Умовний оператор

$rh = Read-Host \
`if ($rh -eq 1) {ipconfig} elseif ($rh -eq 2) {getmac} else {hostname}` \
Якщо умова if () є істинною ($True), виконати дію в {} \
Якщо умова if () є хибною ($False), виконати дію не обов'язкового оператора else \
Умова Elseif йде після умови if для перевірки додаткових умов перед виконанням оператора else. Оператор, який перший поверне $True, скасує виконання додаткових умов \
Якщо передати змінну в умову без оператора, то перевірятиметься наявність значення змінної на $True/$False \
`if ((tnc $srv -Port 80).TcpTestSucceeded) {"Opened port"} else {"Closed port"}`

### Оператори

`-eq` одно (equal) \
`-ceq` враховувати регістр \
`-ne` не дорівнює (not equal) \
`-gt` більше (greater) \
`-ge` більше або одно \
`-lt` менше (less) \
`-le` менше або дорівнює \
`-in` перевірити на наявність (5 -in @(1,2,3,4,5)) \
`-NOT` логічне НІ! (Test-Path $ path) \
`-and` логічне І \
`-or` логічне АБО \
`if ((($1 -eq 1) -and ($2 -eq 2)) -or ($1 -ne 3)) {"$true"} else {"$false"}` дві умови: (якщо $1 = 1 і $2 = 2) або $1 не дорівнює 3

### Pipeline Operators

`Write-Output "First" && Write-Output "Second"` дві успішні команди виконуються \
`Write-Error "Bad" && Write-Output "Second"` перша команда завершується помилкою, через що друга команда не виконується \
`Write-Error "Bad" || Write-Output "Second"` перша команда завершується помилкою, тому виконується друга команда \
`Write-Output "First" || Write-Output "Second"` перша команда виконана успішно, тому друга команда не виконується

### Invocation Operator

`$addr = "8.8.8.8"` \
$ping = "ping" \
`& $ping $addr` запускає текст як команду

`& $ping $addr &` запустити команду на тлі \
`(Get-Job)[-1] | Receive-Job -Keep`

### Спеціальні символи

`\d` число від 0 до 9 (20-07-2022 еквівалент: "\d-d-d-d-d")
`\D` означає будь-який символ, крім цифри. Видалення всіх символів, крім цифр: [int]$("123 test" -replace "\D") \
`\w` літера від "a" до "z" і від "A" до "Z" або число від 0 до 9 \
`\s` пробіл, еквівалент: " " \
`\n` новий рядок \
`\b` маска, визначає початок і кінець цілого словосполучення для пошуку \
`.` позначає будь-який символ, крім нового рядка \
`` екранує будь-який спеціальний символ (метасимвол). Використовується, якщо потрібно вказати конкретний символ замість спеціального ({ } [ ] / \ + * . $ ^ | ?) \
`+` повторюється 1 і більше разів (\s+) \
`{1,25}` квантифікатор, вказує кількість повторень символу зліва направо (від 1 до 25 разів) \
`[]` пошук збігу будь-якої літери, наприклад, [A-z0-9] від A до z та цифри від 0 до 9 ("192.168.1.1" -match "192.1[6-7][0-9]")

### Якорі

`^` або `\A` визначає початок рядка. $url -replace '^','https:'` додати у початок; \
`$` або `\Z` позначають кінець рядка. $ip -replace "\d{1,3}$","0" \
`(?=text)` пошук слова зліва. Пишемо ліворуч праворуч від шуканого (шукає лише цілі словосполучення) "Server:\s(.{1,30})\s(?=$username)" \
`(?<=text)` пошук слова праворуч. $in_time -replace ".+(?<=Last)"` видалити все до слова Last \
`(?!text)` не збігається зі словом зліва \
`(?<!text)` не збігається зі словом праворуч

`$test = "string"` \
`$test -replace ".{1}$"` видалити будь-яку кількість символів в кінці рядка \
`$test -replace "^.{1}"` видалити будь-яку кількість символів на початку рядка \

### Групи захоплення

`$date = '12.31.2021'` \
`$date -replace '^(\d{2}).(\d{2})','$2.$1'` поміняти місцями \
`$1` вміст першої групи в дужках \
`$2` вміст другої групи

# DataType

`$srv.GetType()` дізнатися тип даних \
`$srv -is [string]` перевірка на відповідність типу даних \
`$srv -isnot [System.Object]` перевірка на невідповідність \
`[Object]` масив (BaseType:System.Array) \
`[DateTime]` формат часу (BaseType:System.ValueType) \
`[Bool]/[Boolean]` логічне значення ($True/$False) або 1/0 (1 біт) наявність/відсутність напруги \
`[Byte]` 8-бітове (1 байт) ціле число без знака (0..255) \
`[Int16]` 16-бітове знакове ціле число від -32767 до 32767 (тип даних WORD 0..65535) \
`[Int]` 32-бітове (4 байти) знакове ціле число від -2147483648 до 2147483647 (DWORD) \
`[Int64]` 64-бітове від -9223372036854775808 до 9223372036854775808 (LWORD) \
`[Decimal]` 128-бітове десяткове значення від -79228162514264337593543950335 до 79228162514264337593543950335 \
`[Single]` число з плаваючою комою (32-розрядне) \
`[Double]` число з плаваючою комою з подвійною точністю (64-розрядне) \
`[String]` незмінний рядок символів Юнікоду фіксованої довжини (BaseType:System.Object)

### Math

`[Math] | Get-Member -Static` \
`[math]::Pow(2,4)` 2 в 4 ступені \
`[math]::Truncate(1.8)` грубе округлення, видаляє дробову частину \
`[math]::Ceiling(1.8)` округлює число у велику сторону до найближчого цілого значення \
`[math]::Floor(-1.8)` округлює число в меншу сторону \
`[math]::Min(33,22)` повертає найменше значення двох значень \
`[math]::Max(33,22)` повертає найбільше значення двох значень

### Round

`[double]::Round(87.5, 0)` 88 (непарне), в .NET за замовчуванням використовується округлення в середній точці ToEven, де *.5 значення округляються до найближчого парного цілого числа. \
`[double]::Round(88.5, 0)` 88 (парне) \
`[double]::Round(88.5, 0, 1)` 89 (округляти у велику сторону) \
`[double]::Round(1234.56789, 2)` округлити до 2 символів після коми

### ToString

`(4164539/1MB).ToString("0.00")` розділити на двічі на 1024/1024 і округлити до 3,97

### Char

`[Char]` символ Юнікоду (16-розрядний) \
`$char = $srv.ToCharArray()` розбити рядок [string] на масив [System.Array] з букв \

### Switch
```PowerShell
$MMM = Get-Date -UFormat "%m"
switch($MMM) {
"01" {$Month = 'Jan'}
"02" {$Month = 'Feb'}
"03" {$Month = 'Mar'}
"04" {$Month = 'Apr'}
"05" {$Month = 'May'}
"06" {$Month = 'Jun'}
"07" {$Month = 'Jul'}
"08" {$Month = 'Aug'}
"09" {$Month = 'Sep'}
"10" {$Month = 'Oct'}
"11" {$Month = 'Nov'}
"12" {$Month = 'Dec'}
}
````
### function switch
```PowerShell
Function fun-switch (
[switch]$param
) {
If ($param) {"yes"} else {"no"}
}
fun-switch -param
````
# Bit
````
Двійковий десятковий
1 1
10 2
11 3
100 4
101 5
110 6
111 7
1000 8
1001 9
1010 10
1011 11
1100 12
1101 13
1110 14
1111 15
1 0000 16

Двійковий номер Номер розряду
1 1 0
10 2 1
100 4 2
1000 8 3
1 0000 16 4
10 0000 32 5
100 0000 64 6
1000 0000 128 7
1 0000 0000 256 8

З двійкового => десяткове (1-й варіант за таблицею)
1001 0011 = 1000 0000 + 1 0000 + 10 + 1 = 128 + 16 + 2 + 1 = 147

2-й варіант
7654 3210 (розряди двійкового виразу) = (1*2^7)+(0*2^6)+(0*2^5)+(1*2^4)+(0*2^3)+(0 *2^2)+(1*2^1)+(1*2^0) = 147
[math]::Pow(2,7) + [math]::Pow(2,4) + [math]::Pow(2,1) + [math]::Pow(2,0) = 147` виключити 0 і скласти ступінь

З десяткового => двійкове (1-й варіант за таблицею)
347 відняти найближчі 256 = 91 (+ 1 0000 0000 забрати двійковий залишок)
91 - 64 = 27 найближче 16 (+ 100 0000)
27 - 16 = 11 найближче 8 (+ 1 0000)
11 - 8 = 3 найближче 2 (+ 1000)
3 - 2 = 1 (+ 10)
1 - 1 = 0 (+1)
1 0101 1011

2-й варіант
Послідовний поділ числа на 2, попередньо забираючи залишок для отримання парного числа в меншу сторону
347 - 346 = залишок 1, (347-1)/2 = 173
173 - 172 = залишок 1, (172-1)/2 = 86
86 - 86 = залишок 0, 86/2 = 43
43 - 42 = залишок 1, (43-1)/2 = 21
21 - 20 = залишок 1, (21-1)/2 = 10
10 – 10 = залишок 0, 10/2 = 5
5 - 4 = залишок 1, (5-1)/2 = 2
2 - 2 = залишок 0, 2/2 = 1
1 - 2 = залишок 1, (1-1)/2 = 0
Результат розподілу записується знизу вгору
````
### Bit Convertor
```PowerShell
function ConvertTo-Bit {
param (
[Int]$int
)
[array]$bits = @()
$test = $true
while ($test -eq $true) {
if (($int/2).GetType() -match [double]) {
$int = ($int-1)/2
[array]$bits += 1
}
elseif (($int/2).GetType() -match [int]) {
$int = $int/2
[array]$bits += 0
}
if ($int -eq 0) {
$test = $false
}
}
$bits = $bits[-1..-999]
([string]($bits)) -replace "\s"
}
````
`ConvertTo-Bit 347`
```PowerShell
function ConvertFrom-Bit {
param (
$bit
)
[int]$int = 0
$bits = $bit.ToString().ToCharArray()
$index = ($bits.Count)-1
foreach ($b in $bits) {
if ($b -notlike 0) {
$int += [math]::Pow(2,$index)
}
$index -= 1
}
$int
}
````
`ConvertFrom-Bit 10010011`

`Get-Process pwsh | fl ProcessorAffinity` прив'язка процесу до ядрам, являє собою бітову маску (bitmask), де кожному біту відповідає ядро процесора. Якщо для ядра відзначено подібність (affinity), то біт виставляється в 1, якщо ні - то в 0. Наприклад, якщо вибрано всі 16 ядер, то це 1111 1111 1111 1111 або 65535.
`(Get-Process pwsh).ProcessorAffinity = 15` 0000000000001111 присвоїти 4 перших ядра \
`(Get-Process pwsh).ProcessorAffinity=61440`
`(Get-Process pwsh).ProcessorAffinity = (ConvertFrom-Bit 11110000000000000)`

### Property
`$srv.Count` кількість елементів у масиві \
`$srv.Length` містить кількість символом рядка змінної [string] або кількість значень (рядків) об'єкта \
`$srv.Chars(2)` відобразити 3-й символ у рядку \
`$srv[2]` відобразити 3-й рядок у масиві

### Method
`$srv.Insert(0,"https://")` додати значення перед першим символом \
`$srv.Substring(4)` видалити (з усього масиву) перші 4 символи \
`$srv.Remove(3)` видалити з усього масиву все після 3 символу \
`$string = "123"` створити рядок \
`$int = [convert]::ToInt32($string)` перетворити рядок на тип даних число \
`[string]::Concat($text,$num)` об'єднати змінні в один рядок \
`[string]::Join(":",$text,$num)` об'єднати використовуючи роздільник \
`[string]::Compare($text,$num,$true)` видає 0 при збігу або 1/-1 при розбіжності, $true (без урахування регістру) або $false (з урахуванням регістру) \
`[string]::Equals($text,$num)` здійснює порівняння двох рядків і видає $true при їх збігу або $false при розбіжності \
`[string]::IsNullOrEmpty($text)` перевіряє наявність рядка, якщо рядок порожній $true, якщо немає $false \
`[string]::IsNullOrWhiteSpace($text2)` перевіряє на наявність лише символів пробіл, табуляція або символ нового рядка

### DateTime
`Get-TimeZone` часовий пояс \
`[DateTime]::UtcNow` час у форматі UTC 0 \
`(Get-Date).AddHours(-3)` \
`$Date = (Get-Date -Format "dd/MM/yyyy hh:mm:ss")` \
`$Date = Get-Date -f "dd/MM/yyyy"` отримуємо тип даних [string] \
`[DateTime]$gDate = Get-Date "$Date"` перетворити на тип [DateTime] \
`[int32]$days=($fDate-$gDate).Days` отримати різницю в днях \
`"5/7/07" -as [DateTime]` перетворити вхідні дані на тип даних [DateTime] \
`New-TimeSpan -Start $VBRRP.CreationTimeUTC -End $VBRRP.CompletionTimeUTC` отримати різницю у часі

### Measure-Command
`(Measure-Command {ping ya.ru}).TotalSeconds` дізнатися тільки час виконання \
`(Get-History)[-1] | select @{Name="RunTime"; Expression={$_.EndExecutionTime - $_.StartExecutionTime}},ExecutionStatus,CommandLine` порахувати час роботи останньої [-1] (select -Last 1) виконаної команди та дізнатися її статус

### Timer
`$start_time = Get-Date` зафіксувати час до виконання команди \
`$end_time = Get-Date` зафіксувати час після завершення \
`$time = $end_time - $start_time` розрахувати час роботи скрипта \
`$min = $time.minutes` \
`$sec = $time.seconds` \
`Write-Host "$min хвилин $sec секунд"` \
`$timer = [System.Diagnostics.Stopwatch]::StartNew()` запустити таймер \
`$timer.IsRunning` статус роботи таймера \
`$timer.Elapsed.TotalSeconds` відобразити час з моменту запуску (у секундах) \
`$timer.Stop()` зупинити таймер

### Foreach
`$list = 100..110` створити масив із цифр від 100 до 110 \
`foreach ($srv in $list) {ping 192.168.3.$srv -n 1 -w 50}` $srv зберігає поточний елемент із $list і повторює команду до останнього елемента в масиві \
`$foreach.Current` поточний елемент у циклі \
$foreach.Reset() обнуляє ітерацію, перебір почнеться заново, що призводить до нескінченного циклу \
`$foreach.MoveNext()` перехід до наступного елементу в циклі

### ForEach-Object (%)
100..110 | %{ping -n 1 -w 50 192.168.3.$_ > $null` \
`if ($LastExitCode -eq 0) {Write-Host "192.168.3.$_" -ForegroundColor green` \
`} else {` \
`Write-Host "192.168.3.$_"-ForegroundColor Red}} \
`%` передати цикл через конвейєр (ForEach-Object) \
`$_` змінна циклу та конвейєра ($PSItem) \
`gwmi Win32_QuickFixEngineering | where {$_.InstalledOn.ToString() -match "2022"} | %{($_.HotFixID.Substring(2))}` gwmi створює масив, виведення команди передається where для пошуку підходящих під критерії об'єктів. По конвейєру передається в цикл видалення перших (2) символів методом Substring з усіх об'єктів HotFixID.

### While
`$srv = "yandex.ru"` \
`$out2 = "Є пінг" `\
`$out3 = "Немає пінгу"` \
`$out = $false`` попередньо скинути змінну, While перевіряє умову до запуску циклу \
`While ($out -eq $false){`` поки умова є $true, цикл повторюватиметься \
$out = ping -n 1 -w 50 $srv \
`if ($ out -match "ttl") {$ out = $ true; $out2} else {$out = $false; $out3; sleep 1}`\
`}`

`while ($True){`` запустити нескінченний цикл \
`$result = ping yandex.ru -n 1 -w 50` \
`if ($result -match "TTL"){`` умова, за якої буде виконано break \
`Write-Host "Сайт доступний"` \
`break`` зупинить цикл \
`} else {Write-Host "Сайт недоступний"; sleep 1}`\
`}`

### Try-Catch-Finally
```PowerShell
Try {$out = pping 192.168.3.1}
Catch {Write-Warning "$($error[0])"} # виводить у разі помилки (замість помилки)
finally {$out = "End"} # виконується в кінці у будь-якому випадку
````
### Error
`$Error` виводить усі помилки поточного сеансу \
`$Error[0].InvocationInfo` розгорнутий звіт про помилку \
`$Error.clear()` \
`$LASTEXITCODE` результат виконання останньої команди (0 - успіх) \
`exit 1` код завершення, який повертається $LASTEXITCODE

# Files

`$file = [System.IO.File]::Create("$home\desktop\test.txt")` створити файл \
`$file.Close()` закрити файл \
`[System.IO.File]::ReadAllLines("$home\desktop\test.txt")` прочитати файл \
`$file = New-Object System.IO.StreamReader("$home\desktop\test.txt")` файл буде зайнятий процесом PowerShell \
`$file | gm`\
`$file.ReadLine()` рядковий висновок \
`$file.ReadToEnd()` прочитати файл повністю

### Read/Write Bytes
`$file = [io.file]::ReadAllBytes("$home\desktop\powershell.jpg")` метод відкриває двійковий файл, зчитує його в масив байт і закриває файл \
`[io.file]::WriteAllBytes("$home\desktop\tloztotk-2.jpg",$file)` зберегти байти у файл (можна використовувати для вивантаження двійкових файлів з БД)

`Get-Content $home/desktop\test.txt -Wait` аналог tail \
`Test-Path $path` перевірити доступність шляху \
`Get-ChildItem $path -Filter *.txt -Recurse` відобразити вміст каталогу (Alias: ls/gci/dir) та дочірніх каталогів (-Recurse) та відфільтрувати висновок \
`Get-Location` відобразити поточне розташування (Alias: pwd/gl) \
`Set-Location $path` переміщення каталогами (Alias: cd/sl) \
`Invoke-Item $path` відкрити файл (Alias: ii/start) \
`Get-ItemProperty $env:userprofile\Documents\dns-list.txt | select FullName,Directory,Name,BaseName,Extension` свійтсва файлу \
`Get-ItemProperty -Path $path\* | select FullName,CreationTime,LastWriteTime` властивості файлів вмісту директорії, дата їх створення та останньої зміни \
`New-Item -Path "C:\test\" -ItemType "Directory"` створити директорію (Alias: mkdir/md) \
`New-Item -Path "C:\test\file.txt" -ItemType "File" -Value "Додати текст у файл"` створити файл \
`"test" > "C:\test\file.txt"` замінити вміст \
`"test" >> "C:\test\file.txt"` додати рядок у файл \
`New-Item -Path "C:\test\test\file.txt" -Force` ключ використовується для створення відсутніх в дорозі директорій або перезапису файлу якщо він вже існує \
`Move-Item` переміщення об'єктів (Alias: mv/move) \
`Remove-Item "$path\" -Recurse` видалення всіх файлів усередині каталогу, без запиту підтвердження (Alias: rm/del) \
`Remove-Item $path -Recurse -Include "*.txt","*.temp" -Exclude "log.txt"` видалити всі файли з розширенням txt і temp ([Array]), крім log.txt \
`Rename-Item "C:\test\*.*" "*.jpg"` перейменувати файли за маскою (Alias: ren) \
`Copy-Item` копіювання файлів та каталогів (Alias: cp/copy) \
`Copy-Item -Path "\\server-01\test" -Destination "C:\" -Recurse` копіювати директорію з її вмістом (-Recurse) \
`Copy-Item -Path "C:\*.txt" -Destination "C:\test\"` знак '\' в кінці Destination використовується для перенесення папки всередину зазначеної, відсутність, що це нове ім'я директорії \
`Copy-Item -Path "C:\*" -Destination "C:\test\" -Include '*.txt','*.jpg'` копіювати об'єкти із зазначеним розширенням (Include) \
`Copy-Item -Path "C:\*" -Destination "C:\test\" -Exclude '*.jpeg'` копіювати об'єкти, за винятком файлів з розширенням (Exclude) \
`$log = Copy-Item "C:\*.txt" "C:\test\" -PassThru` вивести результат копіювання (логування) у змінну, можна забирати рядки за допомогою індексів $log[0].FullName

### Clear-env-Temp-14-days
```PowerShell
$ls = Get-Item $env:TEMP\*.tmp # вважати всі файли із зазначеним розширенням
$date = (Get-Date).AddDays(-14)
foreach ($l in $ls) {
if ($l.LastWriteTime -le $date) {
$l.FullName
Remove-Item $l.FullName -Recurse
}
}
````
### Filehash
`Get-Filehash -Algorithm SHA256 "$env:USERPROFILE\Documents\RSA.conf.txt"`

### Microsoft.PowerShell.Archive
`Compress-Archive -Path $sourcepath -DestinationPath $dstpath -CompressionLevel Optimal` архівувати \
`Expand-Archive .\powerlinefonts.zip` розархівувати

# Credential

$Cred = Get-Credential зберігає креди в змінні $Cred.Username і $Cred.Password \
`$Cred.GetNetworkCredential().password` отримати пароль \
`cmdkey /generic:"TERMSRV/$srv" /user:"$username" /pass:"$password"` додати зазначені креди аудентифікації на термінальний сервер для підключення без пароля \
`mstsc /admin /v:$srv` авторизуватись \
`cmdkey /delete:"TERMSRV/$srv"` видалити додані креди аудентифікації з системи \
`rundll32.exe keymgr.dll,KRShowKeyMgr` сховище Stored User Names and Password \
`Get-Service VaultSvc` служба для роботи Credential Manager \
`Install-Module CredentialManager` встановити модуль керування Credential Manager до сховища PasswordVault з PowerShell \
`[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls11,Tls12'` для установки модуля \
`Get-StoredCredential` отримати облікові дані зі сховища Windows Vault \
`Get-StrongPassword` генератор пароля \
`New-StoredCredential -UserName test -Password "123456"` додати обліковий запис \
`Remove-StoredCredential` видалити обліковий запис \
$Cred = Get-StoredCredential | where {$_.username -match "admin"}`\
`$pass = $cred.password` \
`$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass)` \
`[System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)`

### Out-Gridview
`Get-Service -cn $srv | Out-GridView -Title "Service $srv" -OutputMode Single -PassThru | Restart-Service` перезапустити вибрану службу

### Out-File
`Read-Host –AsSecureString | ConvertFrom-SecureString | Out-File "$env:userprofile\desktop\password.txt"` писати у файл. Перетворити пароль у формат SecureString за допомогою шифрування Windows Data Protection API (DPAPI)

### Get-Content (gc/cat/type)
`$password = gc "$env:userprofile\desktop\password.txt" | ConvertTo-SecureString` читати хеш пароля з файлу за допомогою ключів, що зберігаються у профілі поточного користувача, який неможливо прочитати на іншому комп'ютері

### AES Key
`$AESKey = New-Object Byte[] 32` \
`[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($AESKey)` \
`$AESKey | Out-File "C:\password.key"` \
`$Cred.Password | ConvertFrom-SecureString -Key (Get-Content "C:\password.key") | Set-Content "C:\password.txt"` зберегти пароль у файл використовуючи зовнішній ключ \
`$pass = Get-Content "C:\password.txt" | ConvertTo-SecureString -Key (Get-Content "\\Server\Share\password.key")` розшифрувати пароль на другому комп'ютері

# WinEvent

`Get-WinEvent -ListLog *` відобразити всі доступні журнали логів \
`Get-WinEvent-ListLog* | де RecordCount -ne 0 | where RecordCount -ne $null | sort -Descending RecordCount` відобразити не порожні журнали з сортуванням за кількістю записів \
`Get-WinEvent-ListProvider* | ft` відобразити всіх провайдерів програм \
`Get-WinEvent -ListProvider GroupPolicy` знайти в який журнал LogLinks {Application} пишуться логи програми \
`Get-WinEvent -ListProvider *smb*` \
`Get-WinEvent-ListLog* | де logname -match SMB | sort -Descending RecordCount` знайти всі журнали на ім'я \
`Get-WinEvent -LogName "Microsoft-Windows-SmbClient/Connectivity"` \
`Get-WinEvent -ListProvider *firewall*`

### Filter XPath/Hashtable

`Get-WinEvent -FilterHashtable @{LogName="Security";ID=4624}` знайти логі по ID в журналі Security \
`Get-WinEvent -FilterHashtable @{LogName="System";Level=2}` знайти всі записи помилки (1 - критичний, 3 - попередження, 4 - відомості) \
`Get-WinEvent -FilterHashtable @{LogName="System";Level=2;ProviderName="Service Control Manager"}` відфільтрувати на ім'я провайдера

`([xml](Get-WinEvent -FilterHashtable @{LogName="Security";ID=4688} -MaxEvents 1).ToXml()).Event.EventData.Data` відобразити всі властивості, що зберігаються в EventData (Message) \
`Get-WinEvent -FilterHashtable @{logname="security";ID=4688} -MaxEvents 1 | select timecreated,{$_.Properties[5].value}` відфільтрувати час події та ім'я запущеного процесу
````
$query = '
<QueryList>
<Query Id="0" Path="Security">
<Select Path="Security">
		*[System[EventID=4688]] and
*[EventData[Data[@Name="NewProcessName"]="C:\Windows\System32\autochk.exe" or Data[@Name="NewProcessName"]="C:\Windows\System32\services.exe"] ]
</Select>
</Query>
</QueryList>
'

Get-WinEvent -LogName Security -FilterXPath $query
````
### Reboot
````
$query = '
<QueryList>
<Query Id="0" Path="System">
<Select Path="System">
		*[
			System[
			EventID=41 or
			EventID=1074 or
			EventID=1076 or
			EventID=6005 or
			EventID=6006 or
			EventID=6008 or
			EventID=6009 or
			EventID=6013
			]
			]
</Select>
</Query>
</QueryList>
'
Get-WinEvent -LogName System -FilterXPath $query

41 ` Система була перезавантажена без коректного завершення роботи.
1074 Система була коректного вимкнена користувачем або процесом.
1076 Слідує за Event ID 6008 і означає, що перший користувач (з правом вимикання системи) підключився до сервера після несподіваного перезавантаження або вимкнення, вказав причину цієї події.
6005 Запуск "Журналу подій Windows" (Event Log). Вказує на увімкнення системи.
6006 Зупинка «Журналу подій Windows». Вказує на вимкнення системи.
6008 Попереднє вимкнення системи було несподіваним.
6009 Версія операційної системи, зафіксована при завантаженні системи.
6013 Час роботи системи (system uptime) в секундах.
````
### Logon
```PowerShell
$srv = "localhost"
$FilterXPath = '<QueryList><Query Id="0"><Select>*[System[EventID=21]]</Select></Query></QueryList>'
$RDPAuths = Get-WinEvent -ComputerName $srv -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" -FilterXPath $FilterXPath
[xml[]]$xml = $RDPAuths | Foreach {$_.ToXml()}
$EventData = Foreach ($event in $xml.Event) {
New-Object PSObject -Property @{
"Connection Time" = (Get-Date ($event.System.TimeCreated.SystemTime) -Format 'yyyy-MM-dd hh:mm K')
"User Name" = $event.UserData.EventXML.User
"User ID" = $event.UserData.EventXML.SessionID
"User Address" = $event.UserData.EventXML.Address
"Event ID" = $event.System.EventID
}}
$EventData | ft
````
### EventLog

`Get-EventLog -List` відобразити всі кореневі журнали логів та їх розмір \
`Clear-EventLog Application` очистити логи вказаного журналу \
`Get-EventLog -LogName Security -InstanceId 4624` знайти логи по ID у журналі Security

# Firewall
```PowerShell
$days = 5
$obj = @()
$fw = Get-WinEvent "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
foreach ($temp_fw in $fw) {
if ($temp_fw.id -eq 2097) { # 2004
$type = "Added Rule"
}
elseif ($temp_fw.id -eq 2006) {
$type = "Deleted Rule"
}
$port = $temp_fw.Properties[7] | select -ExpandProperty value
$name = $temp_fw.Properties[1] | select -ExpandProperty value
$obj += [PSCustomObject]@{
Time = $ temp_fw.TimeCreated;
Type = $type;
Port = $ port;
Name = $name}
}
$obj | Where-Object time -gt (Get-Date).AddDays(-$days)
````
`New-NetFirewallRule -Profile Any -DisplayName "Open Port 135 RPC" -Direction Inbound -Protocol TCP -LocalPort 135` відкрити in-порт \
`Get-NetFirewallRule | де DisplayName -match kms | select *` знайти правило на ім'я \
`Get-NetFirewallPortFilter | where LocalPort -like 80` знайти чинні правила за номером порту
```PowerShell
Get-NetFirewallRule -Enabled True -Direction Inbound | select -Property DisplayName,
@{Name='Protocol';Expression={($_ | Get-NetFirewallPortFilter).Protocol}},
@{Name='LocalPort';Expression={($_ | Get-NetFirewallPortFilter).LocalPort}},
@{Name='RemotePort';Expression={($_ | Get-NetFirewallPortFilter).RemotePort}},
@{Name='RemoteAddress';Expression={($_ | Get-NetFirewallAddressFilter).RemoteAddress}},
Enabled,Profile
````
### Firewall-Manager

`Install-Module Firewall-Manager` \
`Export-FirewallRules -Name * -CSVFile $home\documents\fw.csv` -Inbound -Outbound -Enabled -Disabled -Allow -Block (фільтр правил експорту) \
`Import-FirewallRules -CSVFile $home\documents\fw.csv`

# Defender

`Import-Module Defender` \
`Get-Command -Module Defender` \
`Get-MpComputerStatus` \
`(Get-MpComputerStatus). AntivirusEnabled` статус роботи антивірусу

`$session = NewCimSession -ComputerName hostname` підключитися до віддаленого комп'ютера, використовується WinRM \
`Get-MpComputerStatus -CimSession $session | fl fullscan*` дізнатися дату останнього сканування на віддаленому комп'ютері

`Get-MpPreference` налаштування \
`(Get-MpPreference).ScanPurgeItemsAfterDelay` час зберігання записів журналу захисника в днях \
`Set-MpPreference -ScanPurgeItemsAfterDelay 30` змінити час зберігання \
`ls "C:\ProgramData\Microsoft\Windows Defender\Scans\History"` \
`Get-MpPreference | select disable*` відобразити статус всіх видів перевірок/сканувань \
`Set-MpPreference -DisableRealtimeMonitoring $true` відключити захист Defender у реальному часі (використовувати тільки ручне сканування) \
`Set-MpPreference -DisableRemovableDriveScanning $false` включити сканування USB накопичувачів \
`Get-MpPreference | select excl*` відобразити список усіх винятків \
`(Get-MpPreference).ExclusionPath`\
`Add-MpPreference -ExclusionPath C:\install` додати директорію на виключення \
`Remove-MpPreference -ExclusionPath C:\install` видалити з винятку \
`New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force` повністю відключити Windows Defender

`Set-MpPreference -SignatureDefinitionUpdateFileSharesSources \\FileShare1\Updates` для оновлення з мережевої папки потрібно попередньо завантажити файли з сигнатурами баз з сайту https://www.microsoft.com/security/portal/definitions/adl.aspx та помістити у мережевий каталог
`Update-MpSignature -UpdateSource FileShares` змінити джерело оновлень (MicrosoftUpdateServer - сервер оновлень MS в інтернеті, InternalDefinitionUpdateServer - внутрішній WSUS сервер) \
`Update-MpSignature` оновити сигнатури

`Start-MpScan -ScanType QuickScan` швидка перевірка або FullScan \
`Start-MpScan -ScanType FullScan -AsJob` \
`Set-MpPreference -RemediationScheduleDay 1-7` вибрати дні, починаючи з неділі або 0 щодня, 8 - скинути \
`Set-MpPreference -ScanScheduleQuickScanTime 14:00:00` \
`Start-MpScan -ScanType CustomScan -ScanPath "C:\Program Files"` сканувати вибрану директорію

`Get-MpThreat` історія загроз та тип загрози (ThreatName: HackTool/Trojan) \
`Get-MpThreatCatalog` Список відомих видів загроз \
`Get-MpThreatDetection` історія захисту (активних та минулі) та ID загрози \
`Get-MpThreat-ThreatID 2147760253`

`ls "C:\ProgramData\Microsoft\Windows Defender\Quarantine\"` директорія зберігання файлів у карантині \
`cd "C:\Program Files\Windows Defender\"` \
`.\MpCmdRun.exe -restore -name $ThreatName` відновити файл з карантину \
`.\MpCmdRun.exe -restore -filepath $path_file`

# WindowsUpdate

Get-Hotfix | Sort-Object -Descending InstalledOn` список встановлених оновлень (інформація з cimv2) \
`Get-Hotfix -Description "Security update"` \
`Get-CimInstance Win32_QuickFixEngineering` \
`Get-Command -Module WindowsUpdate` \
`Get-WindowsUpdateLog` \
`Get-Service uhssvc` служба Microsoft Health Update Tools, яка відповідає за надання оновлень

`Install-Module -Name PSWindowsUpdate -Scope CurrentUser` \
`Import-Module PSWindowsUpdate` \
`Get-Command -Module PSWindowsUpdate` \
`Get-WindowsUpdate` список оновлень для скачати та встановити з сервера WSUS або Microsoft Update \
`Get-WindowsUpdate -Download` завантажити всі оновлення \
`Get-WindowsUpdate –Install` встановити всі оновлення \
`Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot` встановити всі оновлення без перезавантаження \
`Get-WindowsUpdate -KBArticleID KB2267602, KB4533002 -Install` \
`Get-WindowsUpdate -KBArticleID KB2538243 -Hide` приховати оновлення, щоб вони ніколи не встановлювалися \
`Get-WindowsUpdate –IsHidden` відобразити приховані оновлення (Hide-WindowsUpdate) \
`Remove-WindowsUpdate -KBArticleID KB4011634 -NoRestart` видалити оновлення \
`Uninstall-WindowsUpdate` видалити оновлення \
`Add-WUServiceManager` реєстрація сервера оновлення (Windows Update Service Manager) \
`Enable-WURemoting` включити правила Windows Defender, що дозволяють віддалене використання командлета PSWindowsUpdate \
`Get-WUApiVersion` версія Windows Update Agent \
`Get-WUHistory` список усіх інстальованих оновлень (історія оновлень) \
`Get-WUHistory | Where-Object {$_.Title -match "KB4517389"}` пошук поновлення \
`Get-WULastResults` дати останнього пошуку та встановлення оновлень \
`Get-WURebootStatus` перевірити, чи потрібне перезавантаження для застосування конкретного оновлення \
`Get-WUServiceManager` виводить джерела оновлень \
`Get-WUInstallerStatus` статус служби Windows Installer \
`Remove-WUServiceManager` вимкнути Windows Update Service Manager

#DISM

`Get-Command -Module Dism -Name *Driver*` \
`Export-WindowsDriver -Online -Destination C:\Users\Lifailon\Documents\Drivers\` вилучення драйверів з поточної системи (C:\Windows\System32\DriverStore\FileRepository\), вивантажує список файлів, які необхідні для встановлення драйвера (dll ,sys,exe) відповідно до списку файлів, зазначених у розділі [CopyFiles] inf-файлу драйвера. \
`Export-WindowsDriver -Path C:\win_image -Destination C:\drivers` отримати драйвера з офлайн образу Windows, змонтованого в каталог c:\win_image \
`$BackupDrivers = Export-WindowsDriver -Online -Destination C:\Drivers` \
`$BackupDrivers | ft Driver,ClassName,ProviderName,Date,Version,ClassDescription` список драйверів в об'єктному поданні \
`$BackupDrivers | where classname -match printer` \
`pnputil.exe /add-driver C:\drivers\*.inf /subdirs /install` встановити всі (параметр subdirs) драйвера із зазначеної папки (включаючи вкладені)

`sfc /scannow` перевірити цілісність системних файлів за допомогою утиліти SFC (System File Checker), у разі пошуку помилок спробує відновити їх оригінальні копії зі сховища системних компонентів Windows (каталог C:\Windows\WinSxS). Виведення роботи логується в C:\Windows\Logs\CBS з тегом SR \
`Get-ComputerInfo | select *` детальна інформація про систему (WindowsVersion,WindowsEditionId,*Bios*) \
`Get-WindowsImage -ImagePath E:\sources\install.wim` список доступних версій в образі \
`Repair-WindowsImage -Online –ScanHealth` \
`Repair-WindowsImage -Online -RestoreHealth` відновлення сховища системних компонентів \
`Repair-WindowsImage -Online -RestoreHealth -Source E:\sources\install.wim:3 –LimitAccess` відновлення в офлайн режимі з образу за номером індексу

# Scheduled

`$Trigger = New-ScheduledTaskTrigger -At 01:00am -Daily` 1:00 ночі \
`$Trigger = New-ScheduledTaskTrigger –AtLogon` запуск при вході користувача в систему \
`$Trigger = New-ScheduledTaskTrigger -AtStartup` під час запуску системи \
`$User = "NT AUTHORITY\SYSTEM"` \
`$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "$home\Documents\DNS-Change-Tray-1.3.ps1"` \
`$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -NoLogo -NonInteractive -EjecutionPolicy Unrestricted -WindowStyle Hidden -File $home\Documents\DNS-Change-Tray-1.3.ps1"` \
`Register-ScheduledTask -TaskName "DNS-Change-Tray-Startup" -Trigger $Trigger -User $User -Action $Action -RunLevel Highest –Force`

`Get-ScheduledTask | ? state -ne Disabled` список усіх активних завдань \
`Start-ScheduledTask DNS-Change-Tray-Startup` запустити завдання негайно \
`Get-ScheduledTask DNS-Change-Tray-Startup | Disable-ScheduledTask` вимкнути завдання \
`Get-ScheduledTask DNS-Change-Tray-Startup | Enable-ScheduledTask` включити завдання \
`Unregister-ScheduledTask DNS-Change-Tray-Startup` видалити завдання \
`Export-ScheduledTask DNS-Change-Tray-Startup | Out-File $home\Desktop\Task-Export-Startup.xml` експортувати завдання до xml \
`Register-ScheduledTask -Xml (Get-Content $home\Desktop\Task-Export-Startup.xml | Out-String) -TaskName "DNS-Change-Tray-Startup"`

# Network

### ping
`Test-Connection -Count 1 $srv1, $srv2` надіслати icmp-пакет двом хостам \
`Test-Connection $srv -ErrorAction SilentlyContinue` не виводити помилок, якщо хост не відповідає \
`Test-Connection -Source $srv1 -ComputerName $srv2` пінг з віддаленого комп'ютера
```PowerShell
function Test-PingNetwork {
param (
[Parameter(Mandatory,ValueFromPipeline)][string[]]$Network,
[ValidateRange(100,10000)][int]$Timeout = 100
)
$ping = New-Object System.Net.NetworkInformation.Ping
$Network = $Network -replace "0$"
$net = @()
foreach ($r in @(1..254)) {
$net += "$network$r"
}
foreach ($n in $net) {
$ping.Send($n, $timeout) | select @{Name="Address"; Expression={$n -replace ".+\."}}, Status
}
}
````
`Test-PingNetwork -Network 192.168.3.0` \
`Test-PingNetwork -Network 192.168.3.0 -Timeout 1000`

`Get-CimInstance -Class Win32_PingStatus -Filter "Address='127.0.0.1'"` \
`Get-CimInstance -Class Win32_PingStatus -Filter "Address='127.0.0.1'" | Format-Table -Property Address,ResponseTime,StatusCode -Autosize` 0 - успіх \
'127.0.0.1','8.8.8.8' | ForEach-Object -Process {Get-CimInstance -Class Win32_PingStatus -Filter ("Address='$_'") | Select-Object -Property Address,ResponseTime,StatusCode}` \
$ips = 1..254 | ForEach-Object -Process {'192.168.1.' + $_}` сформувати масив з ip-адрес підмережі

### dhcp
`Get-CimInstance -Class Win32_NetworkAdapterConfiguration -Filter "DHCPEnabled=$true"` відобразити адаптери з включеним DHCP \
`$wql = 'SELECT * from Win32_NetworkAdapterConfiguration WHERE IPEnabled=True and DHCPEnabled=False'` \
`Invoke-CimMethod -MethodName ReleaseDHCPLease -Query $wql` включення DHCP на всіх адаптерах \
`Invoke-CimMethod -ClassName Win32_NetworkAdapterConfiguration -MethodName ReleaseDHCPLeaseAll` скасувати оренду адрес DHCP на всіх адаптерах \
`Invoke-CimMethod -ClassName Win32_NetworkAdapterConfiguration -MethodName RenewDHCPLeaseAll` оновити оренду адрес DHCP на всіх адаптерах

### port
`tnc $srv -p 5985` \
`tnc $srv -CommonTCPPort WINRM` HTTP,RDP,SMB \
`tnc ya.ru -TraceRoute -Hops 2` TTL = 2 \
`tnc ya.ru -DiagnoseRouting` маршрутизація до хоста, куди (DestinationPrefix: 0.0.0.0/0) через (NextHop: 192.168.1.254)

### nslookup
`nslookup ya.ru 1.1.1.1` із зазначенням DNS сервера \
`nslookup -type=any ya.ru` вказати тип запису \
`Resolve-DnsName ya.ru -Type MX` ALL,ANY,A,NS,SRV,CNAME,PTR,TXT(spf) \
`[System.Net.Dns]::GetHostEntry("ya.ru")`

### ipconfig
`Get-NetIPConfiguration` \
`Get-NetIPConfiguration -InterfaceIndex 14 -Detailed`

### Adapter
`Get-NetAdapter` \
`Set-NetIPInterface -InterfaceIndex 14 -Dhcp Disabled` відключити DHCP \
`Get-NetAdapter -InterfaceIndex 14 | New-NetIPAddress –IPAddress 192.168.3.99 -DefaultGateway 192.168.3.1 -PrefixLength 24` задати/додати статичну IP-адресу \
`Set-NetIPAddress -InterfaceIndex 14 -IPAddress 192.168.3.98` змінити IP-адреас на адаптері \
`Remove-NetIPAddress -InterfaceIndex 14 -IPAddress 192.168.3.99` видалити IP-адресу на адаптері \
`Set-NetIPInterface -InterfaceIndex 14 -Dhcp Enabled` включити DHCP

### DNSClient
`Get-DNSClientServerAddress` \
`Set-DNSClientServerAddress -InterfaceIndex 14 -ServerAddresses 8.8.8.8`

### DNSCache
`Get-DnsClientCache` відобразити кешовані записи клієнта DNS \
`Clear-DnsClientCache` очистити кеш

### Binding
`Get-NetAdapterBinding -Name Ethernet -IncludeHidden -AllBindings` \
`Get-NetAdapterBinding -Name "Бездротова мережа" -DisplayName "IP версії 6 (TCP/IPv6)" | Set-NetAdapterBinding -Enabled $false` відключити IPv6 на адаптері

### TCPSetting
`Get-NetTCPSetting` \
`Set-NetTCPSetting -SettingName DatacenterCustom,Datacenter -CongestionProvider DCTCP` \
`Set-NetTCPSetting -SettingName DatacenterCustom,Datacenter -CwndRestart True` \
`Set-NetTCPSetting -SettingName DatacenterCustom,Datacenter -ForceWS Disabled`

### netstat
`netstat -anop tcp` -n/-f/-b \
`Get-NetTCPConnection -State Established,Listen | ? LocalPort -Match 3389 `\
`Get-NetTCPConnection -State Established,Listen | ? RemotePort -Match 22`\
`Get-NetUDPEndpoint | ? LocalPort-Match 514 `netstat-ap udp`

### Statistics
`netstat -se` \
`Get-NetAdapterStatistics`

### hostname
`$env:computername` \
`hostname.exe` \
`(Get-CIMInstance CIM_ComputerSystem).Name` \
`(New-Object -ComObject WScript.Network).ComputerName` \
`[System.Environment]::MachineName` \
`[System.Net.Dns]::GetHostName()`

### arp
`ipconfig/all | Select-String "фіз" `grep\
`Get-NetNeighbor -AddressFamily IPv4`
```PowerShell
function Get-ARP {
Param (
$proxy,
$search
)
if (!$proxy) {
$arp = arp -a
}
if ($proxy) {
$arp = icm $proxy {arp -a}
}
$mac = $arp[3..260]
$mac = $mac -replace "^\s\s"
$mac = $mac -replace "\s{1,50}"," "
$mac_coll = New-Object System.Collections.Generic.List[System.Object]
foreach ($m in $mac) {
$smac = $m -split " "
$mac_coll.Add([PSCustomObject]@{
IP = $ smac [0];
MAC = $ smac [1];
Type = $smac[2]
})
}
if ($search) {
if ($search -NotMatch "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}") {
#$ns = nslookup $search
#$ns = $ns[-2]
#$global:ns = $ns -replace "Address:\s{1,10}"
$rdns = Resolve-DnsName $search -ErrorAction Ignore
$ns = $rdns.IPAddress
if ($ns -eq $null) {
return
}
} else {
$ns = $search
}
$mac_coll = $mac_coll | ? ip -Match $ns
}
$mac_coll
}
````
`Get-ARP-search 192.168.3.100` \
`Get-ARP -search 192.168.3.100 -proxy dc-01`

# RDP

`Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber"` відобразити номер поточного порту RDP \
`Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber" -Value "3390"` змінити RDP-порт \
`$(Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\" -Name "fDenyTSConnections").fDenyTSConnections` якщо 0, то включений \
`Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\" -Name "fDenyTSConnections" -Value 0` включити RDP \
`reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f` \
`(gcim -Class Win32_TerminalServiceSetting -Namespace root\CIMV2\TerminalServices).SetAllowTSConnections(0)` включити RDP (для Windows Server) \
`Get-Service TermService | Restart-Service -Force` перезапустити rdp-службу \
`New-NetFirewallRule -Profile Any -DisplayName "RDP 3390" -Direction Inbound -Protocol TCP -LocalPort 3390` відкрити RDP-порт

### IPBan

`auditpol /get /category:*` відобразити всі політики аудиту \
`auditpol /get /category:Вхід/вихід` відобразити локальні політики аудиту для входу та виходу з системи \
`auditpol /set /subcategory:"Вхід до системи" /success:enable /failure:enable` включити локальні політики - Аудит входу до системи \
`auditpol /set /subcategory:"Вихід із системи" /success:enable /failure:enable`

`$url = $($(Invoke-RestMethod https://api.github.com/repos/DigitalRuby/IPBan/releases/latest).assets | Where-Object name -match ".+win.+x64.+" ).browser_download_url` отримати посилання для завантаження останньої версії \
`$version = $(Invoke-RestMethod https://api.github.com/repos/DigitalRuby/IPBan/releases/latest).tag_name` отримати номер останньої версії \
`$path = "$home\Documents\ipban-$version"` шлях для встановлення \
`Invoke-RestMethod $url -OutFile "$home\Downloads\IPBan-$version.zip"` скачати дистрибутив \
`Expand-Archive "$home\Downloads\ipban-$version.zip" -DestinationPath $path` розархівувати в дорогу для встановлення \
`Remove-Item "$home\Downloads\ipban-$version.zip"` видалити дистрибутив \
`sc create IPBan type=own start=delayed-auto binPath="$path\DigitalRuby.IPBan.exe" DisplayName=IPBan` створити службу \
`Get-Service IPBan` статус служби \
`$conf = $(Get-Content "$path\ipban.config")` читаємо конфігурацію \
`$conf = $conf -replace '<add key="Whitelist" value=""/>'''' додати в білий лист домашню мережа для виключення \
`$conf = $conf -replace '<add key="ProcessInternalIPAddresses" value="false"/>','<add key="ProcessInternalIPAddresses" value="true"/>'` включити обробку локальних (внутрішніх) ip- адрес \
`$conf = $conf -replace '<add key="FailedLoginAttemptsBeforeBanUserNameWhitelist" value="20"/>','<add key="FailedLoginAttemptsBeforeBanUserNameWhitelist" value="5"/>''' вказати кількість спроб під'єднання
`$conf = $conf -replace '<add key="ExpireTime" value="01:00:00:00"/>','<add key="ExpireTime" value="00:01:00:00" />'` задати час блокування 1 година \
`$conf > "$path\ipban.config"` оновити конфігурацію \
`Get-Service IPBan | Start-Service` запустити службу
````
Get-NetFirewallRule | Where-Object DisplayName -Match "IPBan" | ForEach-Object {
$Name = $_.DisplayName
Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_ | Select-Object @{Name="Name"; Expression={$Name}},LocalIP,RemoteIP
} # відобразити область застосування правил Брандмауера для IPBan
````
`Get-Content -Wait "$path\logfile.txt"` читати лог \
`Get-Service IPBan | Stop-Service` зупинити службу \
`sc delete IPBan` видалити службу

# shutdown

`shutdown /r /o` перезавантаження в безпечний режим \
`shutdown /s /t 600 /c "Power off after 10 minutes"` вимкнення \
`shutdown /s /f` примусове закриття програм \
`shutdown /a` скасування \
`shutdown /r /t 0 /m \\192.168.3.100` \
`Restart-Computer -ComputerName 192.168.3.100 -Protocol WSMan` через WinRM \
`Restart-Computer –ComputerName 192.168.3.100 –Force` через WMI \
`Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Start\HideShutDown" -Name "value" -Value 1` приховати кнопку вимкнення \
`Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Start\HideRestart" -Name "value" -Value 1` приховати кнопку перезавантаження
```PowerShell
function Start-Shutdown {
<#
.SYNOPSIS
Модули для shutdown and restart the computer at a specified time
.DESCRIPTION
Example:
# Start-Shutdown -Time "18:00"
# Start-Shutdown -Restart -Time "18:00"
# Start-Shutdown -Cancel
.LINK
https://github.com/Lifailon/PS-Commands
#>
param(
[string]$Time,
[switch]$Restart,
[switch]$Cancel
)
if ($Time) {
$currentDateTime = Get-Date
$shutdownTime = Get-Date $Time
if ($shutdownTime -lt $currentDateTime) {
$shutdownTime = $shutdownTime.AddDays(1)
}
$timeUntilShutdown = $shutdownTime - $currentDateTime
$secondsUntilShutdown = [math]::Round($timeUntilShutdown.TotalSeconds)
}
if ($Cancel) {
Start-Process -FilePath "shutdown.exe" -ArgumentList "/a"
} elseif ($Restart) {
Write-Host "The computer will restart after $($timeUntilShutdown.Hours) годин і $($timeUntilShutdown.Minutes) хвилин."
Start-Process -FilePath "shutdown.exe" -ArgumentList "/r", "/f", "/t", "$secondsUntilShutdown"
} else {
Write-Host "На комп'ютері буде shutdown after $($timeUntilShutdown.Hours) годин і $($timeUntilShutdown.Minutes) хвилин."
Start-Process -FilePath "shutdown.exe" -ArgumentList "/s", "/f", "/t", "$secondsUntilShutdown"
}
}
````
# LocalAccounts

`Get-Command -Module Microsoft.PowerShell.LocalAccounts` \
`Get-LocalUser` список користувачів \
`Get-LocalGroup` список груп \
`New-LocalUser "1C" -Password $Password -FullName "1C Domain"` створити користувача \
`Set-LocalUser -Password $Password 1C` змінити пароль \
`Add-LocalGroupMember -Group "Administrators" -Member "1C"` додати до групи Адміністраторів \
`Get-LocalGroupMember "Administrators"` члени групи
```PowerShell
@("vproxy-01","vproxy-02","vproxy-03") | %{
icm $_ {Add-LocalGroupMember -Group "Administrators" -Member "support4"}
icm $_ {Get-LocalGroupMember "Administrators"}
}
````
# SMB

`Get-SmbServerConfiguration` \
`Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force` відключити протокол SMB v1 \
`Get-WindowsFeature | Where-Object {$_.name -eq "FS-SMB1"} | ft Name,Installstate` модуль ServerManager, перевірити чи встановлено компонент SMB1 \
`Install-WindowsFeature FS-SMB1` встановити SMB1 \
`Uninstall-WindowsFeature –Name FS-SMB1 –Remove` видалити SMB1 клієнта (потрібне перезавантаження) \
`Get-WindowsOptionalFeature -Online` модуль DISM, для роботи з компонентами Windows \
`Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -Remove` видалити SMB1 \
`Set-SmbServerConfiguration –AuditSmb1Access $true` включити аудит SMB1 \
`Get-SmbConnection` список активних сесій та використовувана версія SMB (Dialect) \
`Get-SmbOpenFile | select ClientUserName,ClientComputerName,Path,SessionID` список відкритих файлів \
`Get-SmbShare` список мережевих папок \
`New-SmbShare -Name xl-share -Path E:\test` створити нову спільну мережеву папку (розшарити) \
`-EncryptData $True` увімкнути шифрування SMB \
`-Description` ім'я в мережевому оточенні \
`-ReadAccess "domain\username"` доступ до читання \
`-ChangeAccess` доступ на запис \
`-FullAccess` повний доступ \
`-NoAccess ALL` немає прав \
`-FolderEnumerationMode [AccessBased | Unrestricted]` дозволяє приховати в папці мережі об'єкти, на яких у користувача немає доступу за допомогою Access-Based Enumeration (ABE) \
`Get-SmbShare xl-share | Set-SmbShare -FolderEnumerationMode AccessBased` ключити ABE для всіх розшарованих папок \
`Remove-SmbShare xl-share -force` видалити мережевий доступ (кулі) \
`Get-SmbShareAccess xl-share` вивести список доступів безпеки до кулі \
`Revoke-SmbShareAccess xl-share -AccountName Everyone –Force` видалити групу зі списку доступів \
`Grant-SmbShareAccess -Name xl-share -AccountName "domain\XL-Share" -AccessRight Change –force` змінити/додати дозволи на запис (Full,Read) \
`Grant-SmbShareAccess -Name xl-share -AccountName "все" -AccessRight Change –force` \
`Block-SmbShareAccess -Name xl-share -AccountName "domain\noAccess" -Force` примусова заборона \
`New-SmbMapping -LocalPath X: -RemotePath \\$srv\xl-share -UserName support4 -Password password –Persistent $true` підключити мережевий диск \
`-Persistent` відновлення з'єднання після відключення комп'ютера або мережі \
`-SaveCredential` дозволяє зберегти облікові дані користувача для підключення до диспетчера облікових даних Windows Credential Manager \
`Stop-Process -Name "Explorer" | Start-Process -FilePath "C:\Windows\explorer.exe"` перезапустити процес для відображення у провіднику \
`Get-SmbMapping` список підключених мережевих дисків \
`Remove-SmbMapping X: -force` відмонтувати мережевий диск \
`$CIMSession = New-CIMSession –Computername $srv` створити сеанс CIM (аудентифікація на SMB) \
`Get-SmbOpenFile -CIMSession $CIMSession | select ClientUserName,ClientComputerName,Path | Out-GridView -PassThru | Close-SmbOpenFile -CIMSession $CIMSession -Confirm:$false –Force` закрити файли (відкрити до них мережний доступ)

### Get-Acl
`(Get-Acl \\$srv\xl-share).access` доступ ACL на рівні NTFS \
`Get-Acl C:\Drivers | Set-Acl C:\Distr` скопіювати NTFS дозволи з однієї папки та застосувати їх на іншу

### NTFSSecurity
`Install-Module -Name NTFSSecurity -force` \
`Get-Item "\$srv\xl-share" | Get-NTFSAccess`\
`Add-NTFSAccess -Path "\\$srv\xl-share" -Account "domain\xl-share" -AccessRights Fullcontrol -PassThru` додати \
`Remove-NTFSAccess -Path "\\$srv\xl-share" -Account "domain\xl-share" -AccessRights FullControl -PassThru` видалити \
`Get-ChildItem -Path "\$srv\xl-share" -Recurse -Force | Clear-NTFSAccess` видалити всі дозволи, без видалення успадкованих дозволів \
`Get-ChildItem -Path "\$srv\xl-share" -Recurse -Force | Enable-NTFSAccessInheritance` включити NTFS успадкування для всіх об'єктів у каталозі

### Storage
`Get-Command -Module Storage` \
`Get-Disk` список логічних дисків \
`Get-Partition` відобразити розділи на всіх дисках \
`Get-Volume` список логічних розділів \
`Get-PhysicalDisk` список фізичних дисків \
`Initialize-Disk 1 –PartitionStyle MBR` ініціалізувати диск \
`New-Partition -DriveLetter D –DiskNumber 1 -Size 500gb` створити розділ (виділити все місце -UseMaximumSize) \
`Format-Volume -DriveLetter D -FileSystem NTFS -NewFileSystemLabel Disk-D` форматувати розділ \
`Set-Partition -DriveLetter D -IsActive $True` зробити активним \
`Remove-Partition -DriveLetter D –DiskNumber 1` видалити розділ \
`Clear-Disk -Number 1 -RemoveData` очистити диск \
`Repair-Volume –driveletter C –Scan` Check disk \
`Repair-Volume –driveletter C –SpotFix` \
`Repair-Volume –driverletter C -Scan –Cimsession $CIMSession`

### iSCSI
`New-IscsiVirtualDisk -Path D:\iSCSIVirtualDisks\iSCSI2.vhdx -Size 20GB` створити динамічний vhdx-диск (для фіксованого розміру -UseFixed) \
`New-IscsiServerTarget -TargetName iscsi-target-2 -InitiatorIds "IQN:iqn.1991-05.com.microsoft:srv3.contoso.com"` створити Target \
`Get-IscsiServerTarget | fl TargetName, LunMappings` \
`Connect-IscsiTarget -NodeAddress "iqn.1995-05.com.microsoft:srv2-iscsi-target-2-target" -IsPersistent $true` підключитися ініціатором до таргету \
`Get-IscsiTarget | fl`\
`Disconnect-IscsiTarget -NodeAddress "iqn.1995-05.com.microsoft:srv2-iscsi-target-2-target" -Confirm:$false` відключитися

# ActiveDirectory

### RSAT (Remote Server Administration Tools)
`DISM.exe /Online /add-capability /CapabilityName:Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 /CapabilityName:Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0` \
`Add-WindowsCapability –online –Name Rsat.Dns.Tools~~~~0.0.1.0` \
`Add-WindowsCapability -Online -Name Rsat.DHCP.Tools~~~~0.0.1.0` \
`Add-WindowsCapability –online –Name Rsat.FileServices.Tools~~~~0.0.1.0` \
`Add-WindowsCapability -Online -Name Rsat.WSUS.Tools~~~~0.0.1.0` \
`Add-WindowsCapability -Online -Name Rsat.CertificateServices.Tools~~~~0.0.1.0` \
`Add-WindowsCapability -Online -Name Rsat.RemoteDesktop.Services.Tools~~~~0.0.1.0` \
`Get-WindowsCapability -Name RSAT* -Online | Select-Object -Property DisplayName, State` відобразити список встановлених компаній

### Import-Module ActiveDirectory
`$Session = New-PSSession -ComputerName $srv` -Credential $cred` \
`Export-PSsession -Session $Session -Module ActiveDirectory -OutputModule ActiveDirectory` експортувати модуль з віддаленої сесії (наприклад, з DC) \
`Remove-PSSession -Session $Session` \
`Import-Module ActiveDirectory` \
`Get-Command -Module ActiveDirectory`

### ADSI (Active Directory Service Interface)
`$d0 = $env:userdnsdomain` \
`$d0 = $d0 -split "\."` \
`$d1 = $d0[0]` \
`$d2 = $d0[1]` \
`$group = [ADSI]"LDAP://OU=Domain Controllers,DC=$d1,DC=$d2"` \
`$group | select *`

`$Local_User = [ADSI]"WinNT://./Адміністратор,user"` \
`$Local_User | Get-Member`\
`$Local_User.Description` \
`$Local_User.LastLogin` час останньої авторизації локального користувача

### LDAP (Lightweight Directory Access Protocol)
`$ldapsearcher = New-Object System.DirectoryServices.DirectorySearcher` \
`$ldapsearcher.SearchRoot = "LDAP://OU=Domain Controllers,DC=$d1,DC=$d2"` \
`$ldapsearcher.Filter = "(objectclass=computer)"` \
`$dc = $ldapsearcher.FindAll().path`

$usr = $env:username Список груп поточного користувача \
`$ldapsearcher = New-Object System.DirectoryServices.DirectorySearcher` \
`$ldapsearcher.Filter = "(&(objectCategory=User)(samAccountName=$usr))"` \
`$usrfind = $ldapsearcher.FindOne()` \
`$groups = $usrfind.properties.memberof -replace "(,OU=.+)"` \
`$groups = $groups -replace "(CN=)"`

DC (Domain Component) - компонент доменного імені \
OU (Organizational Unit) - організаційні підрозділи (type), що використовуються для впорядкування об'єктів \
Container - так само використовується для впорядкування об'єктів, контейнери на відміну від підрядів не можуть бути перейменовані, видалені, створені або пов'язані з об'єктом групової політики (Computers, Domain Controllers, Users) \
DN (Distinguished Name) – унікальне ім'я об'єкта та місцезнаходження в лісі AD. У DN описується вміст атрибутів у дереві (шлях навігації), необхідний для доступу до конкретного запису або пошуку \
CN (Common Name) – загальне ім'я

`(Get-ADObject (Get-ADRootDSE).DefaultNamingContext -Properties wellKnownObjects).wellKnownObjects` відобразити відобразити контейнери за замовчуванням \
`redircmp OU=Client Computers,DC=root,DC=domain,DC=local` змінити контейнер комп'ютерів за умовчанням \
`redirusr` змінити контейнер користувачів за замовчуванням

### LAPS (Local Admin Password Management)
`Import-module AdmPwd.ps` імпортувати модуль \
`Get-AdmPwdPassword -ComputerName NAME` переглянути пароль \
`Reset-AdmPwdPassword -ComputerName NAME` змінити пароль \
`Get-ADComputer -Filter * -SearchBase "DC=$d1,DC=$d2" | Get-AdmPwdPassword -ComputerName {$_.Name} | select ComputerName,Password,ExpirationTimestamp | Out-GridView`\
`Get-ADComputer -Identity $srv | Get-AdmPwdPassword -ComputerName {$_.Name} | select ComputerName,Password,ExpirationTimestamp`

### Recycle Bin
Видалені об'єкти зберігаються в кошику AD протягом часу поховання (визначається в атрибуті домену msDS-deletedObjectLifetime), заданому для лісу. За промовчанням це 180 днів. Якщо цей термін минув, об'єкт все ще залишається в контейнері Deleted Objects, але більшість його атрибутів та зв'язків очищаються (Recycled Object). Після закінчення періоду tombstoneLifetime (за замовчуванням також 180 днів, але можна збільшити) об'єкт повністю видаляється з AD автоматичним процесом очищення. \
`Get-ADForest domain.local` відобразити рівень роботи лісу \
`Set-ADForestMode -Identity domain.local -ForestMode Windows2008R2Forest -force` збільшити рівень роботи лісу \
`Enable-ADOptionalFeature –Identity "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=domain,DC=local" –Scope ForestOrConfigurationSet –Target " domain.local"` включити корзину \
`Get-ADOptionalFeature "Recycle Bin Feature" | select-object name,EnabledScopes` якщо значення EnabledScopes не порожнє, значить в домені кошик Active Directory включений \
`Get-ADObject -Filter 'Name -like "*tnas*"' -IncludeDeletedObjects` знайти віддалену (Deleted: True) УЗ (ObjectClass: user) в AD \
`Get-ADObject -Filter 'Name -like "*tnas*"' -IncludeDeletedObjects -Properties *| select-object Name, sAMAccountName, LastKnownParent, memberOf, IsDeleted | fl` перевірити значення атрибуту IsDeleted, контейнер, в якому знаходився користувачеві перед видаленням (LastKnownParent) та список груп, в яких він складався \
`Get-ADObject –filter {Deleted -eq $True -and ObjectClass -eq "user"} –includeDeletedObjects` вивести список віддалених користувачів \
`Restore-ADObject -Identity "3dc33c7c-b912-4a19-b1b7-415c1395a34e"` відновити за значенням атрибута ObjectGUID \
`Get-ADObject -Filter 'SAMAccountName -eq "tnas-01"' –IncludeDeletedObjects | Restore-ADObject` відновити за SAMAccountName \
`Get-ADObject -Filter {Deleted -eq $True -and ObjectClass -eq 'group' -and Name -like '*Allow*'} –IncludeDeletedObjects | Restore-ADObject –Verbose` відновити групу чи комп'ютер

### thumbnailPhoto
`$photo = [byte[]](Get-Content C:\Install\adm.jpg -Encoding byte)` перетворити файл картинки на масив байтів (jpeg/bmp файл, розміром фото до 100 Кб і роздільною здатністю 96?96) \
`Set-ADUser support4 -Replace @{thumbnailPhoto=$photo}` встановити значення атрибута thumbnailPhoto

### ADDomainController
`Get-ADDomainController` виводить інформацію про поточний контролер домену (LogonServer), який використовується даним комп'ютером для аутентифікації (DC вибирається при завантаженні відповідно до топології сайтів AD) \
`Get-ADDomainController -Discover -Service PrimaryDC` знайти контролер за участю PDC в домені \
`Get-ADDomainController-Filter* | ft HostName,IPv4Address,Name,Site,OperatingSystem,IsGlobalCatalog` список всі DC, приналежність до сайту, версії ОС та GC

При завантаженні ОС служба NetLogon робить DNS запит зі списком контролерів домену (до SRV запису _ldap._tcp.dc._msdcs.domain_), DNS повертає список DC у домені із записом Service Location (SRV). Клієнт робить LDAP запит до DC для визначення сайту AD на свою IP адресу. Клієнт через DNS запитує список контролерів домену на сайті (у розділі _tcp.sitename._sites...).

USN (Update Sequence Numbers) – лічильник номера послідовного оновлення, який існує у кожного об'єкта AD. При реплікації контролери обмінюються значеннями USN, об'єкт з нижчим USN буде при реплікації перезаписаний об'єктом з вищим USN. Знаходиться у властивостях – Object (включити View – Advanced Features). Кожен контролер домену містить окремий лічильник USN, який починає відлік у момент запуску процесу Dcpromo та продовжує збільшувати значення протягом усього часу існування контролера домену. Значення лічильника USN збільшується щоразу, коли на контролері домену відбувається транзакція, це операції створення, оновлення чи видалення об'єкта.

`Get-ADDomainController-Filter* | % {` відобразити USN об'єкта на всіх DC в домені` \
`Get-ADUser -Server $_.HostName -Identity support4 -Properties uSNChanged | select SamAccountName,uSNChanged` \
`}`

`dcpromo /forceremoval` примусово здійснить зниження ролі контролера домену рівня рядового сервера. Після зниження ролі виконується видалення всіх посилань у домені цього контролер. Далі здійснює включення сервера до складу домену, і виконання зворотного процесу, тобто. підвищення сервера рівня контролера домену.

### ADComputer
`nltest /DSGETDC:$env:userdnsdomain` дізнатися на якому DC аудентифікований хост (Logon Server) \
`nltest /SC_RESET:$env:userdnsdomain\srv-dc2.$env:userdnsdomain` переключити комп'ютер на інший контролер домену AD вручну (The command completed successfully) \
`Get-ADComputer –Identity $env:computername -Properties PasswordLastSet` час останньої зміни пароля на сервері \
`Test-ComputerSecureChannel –verbose` перевірити довірчі відносини з доменом (чи відповідає локальний пароль комп'ютера паролю, що зберігається в AD) \
`Reset-ComputerMachinePassword -Credential domain\admin` примусово оновити пароль \
`Netdom ResetPWD /Server:dc-01 /UserD:domain\admin /PasswordD:*` скинути хеш пароля комп'ютера в домені (перезавантаження не потрібно) \
`Search-ADAccount -AccountDisabled -ComputersOnly | select Name,LastLogonDate,Enabled` відобразити всі вимкнені комп'ютери

`Get-ADComputer-Filter*-Properties* | select name` список усіх комп'ютерів у домені (Filter), вивести всі властивості (Properties) \
`Get-ADComputer -Identity $srv -Properties * | ft Name,LastLogonDate,PasswordLastSet,ms-Mcs-AdmPwd -Autosize` конкретного комп'ютера в AD (Identity) \
`Get-ADComputer -SearchBase "OU=Domain Controllers,DC=$d1,DC=$d2" -Filter * -Properties * | ft Name, LastLogonDate, distinguishedName -Autosize` пошук у базі за DN (SearchBase)

`(Get-ADComputer -Filter {enabled -eq "true"}).count` отримати загальну кількість активних (незаблокованих) комп'ютерів \
`(Get-ADComputer -Filter {enabled -eq "true" -and OperatingSystem -like "*Windows Server 2016*"}).count` кількість активних комп'ютерів з ОС WS 2016

`Get-ADComputer-Filter*-Properties* | select @{Label="Ping Status"; Expression={` \
`$ping = ping -n 1 -w 50 $_.Name` \
`if ($ping -match "TTL") {"Online"} else {"Offline"}` \
`}}, `\
`@{Label="Status"; Expression={` \
`if ($_.Enabled -eq "True") {$_.Enabled -replace "True","Active"} else {$_.Enabled -replace "False","Blocked"}` \
`}}, Name, IPv4Address, OperatingSystem, @{Label="UserOwner"; Expression={$_.ManagedBy -replace "(CN=|,.+)"}` \
`},Created | Out-GridView`

### ADUser
`Get-ADUser -Identity support4 -Properties *` список усіх атрибутів \
`Get-ADUser -Identity support4 -Properties DistinguishedName, EmailAddress, Description` шлях DN, email та опис \
`Get-ADUser -Filter {(Enabled -eq "True") -and (mail -ne "null")} -Properties mail | ft Name,mail` список активних користувачів і є поштова скринька \
`Get-ADUser -Filter {SamAccountName -like "*"} | Measure-Object` порахувати кількість всіх акаунтів (Count) \
`Get-ADUser -Filter * -Properties WhenCreated | sort WhenCreated | ft Name, whenCreated` дата створення \
`Get-ADUser -Identity support4 -property LockedOut | select samaccountName,Name,Enabled,Lockedout` \
`Enabled=True` обліковий запис включений - так \
`Lockedout=False` обліковий запис заблокований (наприклад, політикою паролів) - немає \
`Get-ADUser -Identity support4 | Unlock-ADAccount` розблокувати обліковий запис \
`Disable-ADAccount -Identity support4` вимкнути обліковий запис \
`Enable-ADAccount -Identity support4` включити обліковий запис \
`Search-ADAccount -LockedOut` знайти всі заблоковані облікові записи \
`Search-ADAccount -AccountDisabled | select Name,LastLogonDate,Enabled` відобразити всі відключені облікові записи з часом останнього входу

`Get-ADUser -Identity support4 -Properties PasswordLastSet,PasswordExpired,PasswordNeverExpires` \
`PasswordLastSet` час останньої зміни пароля \
`PasswordExpired=False` пароль минув - ні \
`PasswordNeverExpires=True` термін дії пароля не закінчується - так \
`Set-ADAccountPassword support4 -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "password" -Force -Verbose)` змінити пароль облікового запису \
`Set-ADUser -Identity support4 -ChangePasswordAtLogon $True` зміна пароля при наступному вході в систему

`$day = (Get-Date).adddays(-90)` \
`Get-ADUser -filter {(passwordlastset -le $day)} | ft` користувачі, які не змінювали свій пароль більше 90 днів

`$day = (Get-Date).adddays(-30)` \
`Get-ADUser -filter {(Created -ge $day)} -Property Created | select Name,Created` Нові користувачі за 30 днів

`$day = (Get-Date).adddays(-360)` \
`Get-ADUser -Filter {(LastLogonTimestamp -le $day)} -Property LastLogonTimestamp | select Name,SamAccountName,@{n='LastLogonTimestamp';e={[DateTime]::FromFileTime($_.LastLogonTimestamp)}} | sort -Descending LastLogonTimestamp` користувачі, які не логінилися більше 360 днів. Реплікація атрибуту LastLogonTimestamp складає від 9 до 14 днів. \
`| Disable-ADAccount $_.SamAccountName` заблокувати \
`-WhatIf` відобразити висновок без застосування змін

### ADGroupMember
`(Get-ADUser -Identity support4 -Properties MemberOf).memberof` список груп у яких складається користувач \
`Get-ADGroupMember -Identity "Domain Admins" | Select Name,SamAccountName` список користувачів у групі \
`Add-ADGroupMember -Identity "Domain Admins" -Members support5` додати до групи \
`Remove-ADGroupMember -Identity "Domain Admins" -Members support5 -force` видалити з групи \
`Get-ADGroup-filter* | where {!($_ | Get-ADGroupMember)} | Select Name` відобразити список порожніх груп (-Not)

### ADReplication
`Get-Command -Module ActiveDirectory -Name *Replication*` список усіх командлетів модуля \
`Get-ADReplicationFailure -Target dc-01` Список помилок реплікації з партнерами \
`Get-ADReplicationFailure -Target $env:userdnsdomain -Scope Domain` \
`Get-ADReplicationPartnerMetadata -Target dc-01 | select Partner,LastReplicationAttempt,LastReplicationSuccess,LastReplicationResult,LastChangeUsn` час останньої та час успішної реплікації з партнерами \
`Get-ADReplicationUpToDatenessVectorTable -Target dc-01` Update Sequence Number (USN) збільшується щоразу, коли на контролері домену відбувається транзакція (операції створення, оновлення або видалення об'єкта), при реплікації DC обмінюються значеннями USN, об'єкт з нижчим USN буде перезаписано високим USN.

# repadmin

`repadmin /replsummary` відображає час останньої реплікації на всіх DC за напрямом (Source та Destination) та їх стан з урахуванням партнерів \
`repadmin /showrepl $srv` відображає всіх партнерів по реплкації та їх статус для всіх розділів Naming Contexts (DC=ForestDnsZones, DC=DomainDnsZones, CN=Schema, CN=Configuration) \
`repadmin /replicate $srv2 $srv1 DC=domain,DC=local ` виконати реплікацію з $srv1 на $srv2 тільки вказаний розділу домену \
`repadmin /SyncAll /AdeP` запустити міжсайтову вихідну реплікацію всіх розділів від поточного сервера з усіма реплікаційними партнерами \
`/A` виконати для всіх розділів NC \
`/d` у повідомленнях ідентифікувати сервери за DN (замість GUID DNS - глобальним унікальним ідентифікаторам) \
`/e` міжсайтова синхронізація (за замовчуванням синхронізує лише з DC поточного сайту) \
`/P` сповіщати про зміни з цього сервера (за замовчуванням: опитувати про зміни) \
`repadmin /Queue $srv` відображає кількість запитів вхідної реплікації (черга), яку необхідно обробити (причиною може бути велика кількість партнерів або формування 1000 об'єктів скриптом) \
`repadmin /showbackup *` дізнатися дату останнього Backup

`Error: 1722` сервер rpc недоступний (помилка відкату реплікації). Перевірити ім'я домену в налаштуваннях мережного адаптера, першим повинен йти адреса DNS-сервера іншого контролера домену, другим свою адресу. \
`Get-Service -ComputerName $srv | select name,status | ? name -like "RpcSs"`\
`Get-Service -ComputerName $srv -Name RpcSs -RequiredServices` залежні служби \
Залежні служби RPC: \
"Служба відомостей про підключені мережі" - має бути увімкнений відкладений запуск. Якщо служба спрацьовує до служби списку мереж, може падати зв'язок з доменом (netlogon) \
"Центр розповсюдження ключів Kerberos"
"DNS-сервер" \
`nslookup $srv` \
`tnc $srv -p 135` \
`repadmin /retry` повторити спробу прив'язки до цільового DC, якщо була помилка 1722 або 1753 (RPC недоступний)

`repadmin /showrepl $srv` \
`Last attempt @ 2022-07-15 10:46:01 завершена з помилкою, результат 8456 (0x2108)` під час перевірки showrepl цього партнера, його помилка: 8457 (0x2109) \
`Last success @ 2022-07-11 02:29:46` останній успіх \
Коли реплікація автоматично відключена, ОС записує в DSA - no writable одне з чотирьох значень: \
`Path: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NTDS\Parameters` \
`Dsa Not Writable` \
`#define DSA_WRITABLE_GEN 1` версія лісу несумісна з ОС \
`#define DSA_WRITABLE_NO_SPACE 2` на диску, де розміщена база даних Active Directory або файли журналів (логи), недостатньо вільного місця \
`#define DSA_WRITABLE_USNROLLBCK 4` відкат USN стався через неправильний відкат бази даних Active Directory у часі (відновлення зі снапшота) \
`#define DSA_WRITABLE_CORRUPT_UTDV 8` вектор актуальності пошкоджено на локальному контролері домену

# dcdiag

`dcdiag /s:<DomainController> [/n:<NamingContext>] [[/u:<domain\user>] [/p:<password>]] [{/a|/e}{/q|/v }] [/f:<LogFile>] [/ferr:<ErrorLog>] [/test:<test>] [/fix]` \
`dcdiag /Test:replications /s:dc-01` відображає помилки реплікації \
`dcdiag /Test:DNS /e /v /q` тест DNS \
`/a` перевірка всіх серверів даного сайту \
`/e` перевірка всіх серверів підприємства \
`/q` виводити тільки повідомлення про помилки \
`/v` виводити докладну інформацію \
`/fix` автоматично виправляє помилки \
`/test:` \
`NetLogons` перевірка наявності прав на виконання реплікації \
`Connectivity` перевіряє реєстрацію DNS для кожного контролера домену, відправляє тестовий ехо-пакет на кожен контролер домену та перевіряє підключення за протоколами LDAP та RPC до кожного контролера домену \
`Services` перевіряє працездатність всіх служб, необхідних для роботи контролера домену, на вказаному контролері домену \
`Systemlog` перевіряє наявність помилок у журналах контролера домену \
`FRSEvent` перевіряє помилки реплікації в роботі служби реплікації файлів, що може означати наявність проблем у реплікації SYSVOL і, таким чином, цілісності копій об'єктів групових політик \
`FSMOCheck` не перевіряє ролі господарів операцій, а натомість запитує сервер глобального каталогу, первинний контролер домену, кращий сервер часу, сервер часу та центр розповсюдження ключів (контролер домену може підключитися до KDC, PDC, сервера глобального каталогу) \
`KnowsOfRoleHolders` перевіряє можливість підключення контролерів домену до всіх п'яти господарів операцій (ролями FSMO) \
`MachineAccount` перевіряє правильність реєстрації облікового запису цільового комп'ютера та правильність оголошень служб цього комп'ютера (коректність довірчих відносин з доменом). Якщо виявлено помилку, її можна виправити за допомогою утиліти dcdiag, вказавши параметри /fixmachineaccount або /recreatemachineaccount \
Advertising перевіряє, чи правильно контролер домену повідомляє про себе і про свою роль господаря операцій. Цей тест завершиться невдало, якщо служба NetLogon не запущена \
`CheckSDRefDom` перевіряє правильність доменів посилань дескрипторів безпеки для кожного розділу каталогів програм \
`CrossRefValidation` перевіряє правильність перехресних посилань для доменів \
`RRSSysvol` перевіряє стан готовності для FRS SYSVOL \
Intersite перевіряє наявність помилок, які можуть перешкодити нормальній реплікації між сайтами. Компанія Microsoft попереджає, що іноді результати цього тесту можуть виявитися неточними.
`KCCEvent` перевіряє безпомилковість створення об'єктів з'єднань для реплікації між сайтами \
NCSecDesc перевіряє правильність дозволів для реплікації в дескрипторах безпеки для заголовків контексту іменування \
`ObjectsReplicated` перевіряє правильність реплікації агента сервера каталогів та об'єктів облікових записів комп'ютерів \
`OutboundSecureChannels` перевіряється наявність безпечних каналів між усіма контролерами домену в домені \
`Replications` перевіряє можливість реплікації між контролерами домену та повідомляє про всі помилки при реплікації \
`RidManager` перевіряє працездатність та доступність господаря відносних ідентифікаторів \
`VerifyEnterpriseReferences` перевіряє дійсність системних посилань служби реплікації файлів для всіх об'єктів на всіх контролерах домену в лісі \
`VerifyReferences` перевіряє дійсність системних посилань служби реплікації файлів для всіх об'єктів на вказаному контролері домену \
VerifyReplicas перевіряє дійсність всіх розділів каталогу програми на всіх серверах, що беруть участь у реплікації.

# ntdsutil

Перенесення БД AD (ntds.dit): \
`Get-Acl C:\Windows\NTDS | Set-Acl D:\AD-DB` скопіювати NTFS дозволи на новий каталог \
`Stop-Service -ComputerName dc -name NTDS` зупинити службу Active Directory Domain Services \
`ntdsutil` запустити утиліту ntdsutil \
`activate instance NTDS` вибрати активний екземпляр бази AD \
`files` перейдемо в контекст files, в якому можливе виконання операції з файлами бази ntds.dit \
`move DB to D:\AD-DB\` перенести базу AD у новий каталог (попередньо його створити) \
`info` перевірити, що БД знаходиться в новому каталозі \
`move logs to D:\AD-DB\` перемістимо до того ж каталогу файли з журналами транзакцій \
`quit` \
`Start-Service -ComputerName dc -name NTDS`

Скидання пароля DSRM (режим відновлення служб каталогів): \
`ntdsutil` \
`set dsrm password` \
`reset password on server NULL` \
Новий пароль \
Підтвердження пароля \
`quit` \
`quit`

Синхронізувати з паролем УЗ AD: \
`ntdsutil` \
`set dsrm password` \
`sync from domain account dsrmadmin` \
`quit` \
`quit`

Помилка 0x00002e2 під час завантаження ОС. \
Завантажитись у режимі відновлення WinRE (Windows Recovery Environment) - Startup Settings - Restart - DSRM (Directory Services Restore Mode) \
`reagentc /boottore` shutdown /f /r /o /t 0 перезавантаження в режимі WinRE - ОС на базі WinPE (Windows Preinstallation Environment), образ winre.wim знаходиться на прихованому розділі System Restore \
На контролері домену єдиний локальний обліковий запис - адміністратор DSRM. Пароль створюється під час встановлення ролі контролера домену ADDS на сервері (SafeModeAdministratorPassword). \
`ntdsutil` \
`activate instance ntds` \
`Files` \
`Info` \
`integrity` перевірити цілісність БД
Помилка: Failed to Open DIT for AD DS/LDS instance NTDS. Error -2147418113 \
`mkdir c:\ntds_bak` \
`xcopy c:\Windows\NTDS\*.* c:\ntds_bak` backup вмісту каталогу з БД \
`esentutl /gc:\windows\ntds\ntds.dit` перевіримо цілісність файлу \
Висновок: Integrity check completed. Database is CORRUPTED помилка, база AD пошкоджена \
`esentutl /pc:\windows\ntds\ntds.dit` виправити помилки \
Висновок: Operation completed successfully в xx seconds. немає помилок \
`esentutl /gc:\windows\ntds\ntds.dit` перевіримо цілісність файлу \
Виконати аналіз семантики бази за допомогою ntdsutil: \
`ntdsutil` \
`activate instance ntds` \
`semantic database analysis` \
`go` \
`go fixup` виправити семантичні помилки \
Стиснути файл БД: \
`activate instance ntds` \
`files` \
`compact to C:\Windows\NTDS\TEMP` \
`copy C:\Windows\NTDS\TEMP\ntds.dit C:\Windows\NTDS\ntds.dit` замінити оригінальний файл ntds.dit \
`Del C:\Windows\NTDS\*.log` видалити всі лог файли з каталогу NTDS

# GPO

`Get-Command -Module GroupPolicy` \
`Get-GPO -Domain domain.local -All | ft` \
`Get-GPO -Name LAPS` \
`[xml](Get-GPOReport LAPS -ReportType Xml)` \
`Get-GPPermission -Name LAPS -All` \
`Get-GPO LAPS | New-GPLink -Target "ou=servers,dc=domain,dc=local"` \
`Set-GPLink -Name LAPS -Target "ou=servers,dc=domain,dc=local" -LinkEnabled No` \
`Backup-GPO -Name LAPS -Path "$home\Desktop"` \
`Backup-GPO -All-Path "$home\Desktop"` \
`Restore-GPO -Name LAPS -Path C:\Backup\GPOs\`

# ServerManager

`Get-Command *WindowsFeature*` source module ServerManager \
`Get-WindowsFeature -ComputerName "localhost"` \
`Get-WindowsFeature | where Installed -eq $True` список встановлених ролей та компонентів \
`Get-WindowsFeature | where FeatureType -eq "Role"` відсортувати за списком ролей \
`Install-WindowsFeature -Name DNS` встановити роль \
`Get-Command *DNS*` \
`Get-DnsServerSetting -ALL` \
`Uninstall-WindowsFeature -Name DNS` видалити роль

### PSWA
`Install-WindowsFeature -Name WindowsPowerShellWebAccess -IncludeManagementTools` \
`Install-PswaWebApplication -UseTestCertificate` Створити веб-додаток /pswa \
`Add-PswaAuthorizationRule -UserGroupName "$domain\Domain Admins" -ComputerName * -ConfigurationName * -RuleName "For Admins"` додати права авторизації

### WSB (Windows Server Backup)
При створенні backup DC через WSB створюється копія стану системи (System State), куди потрапляє база AD (NTDS.DIT), об'єкти групових політик, вміст каталогу SYSVOL, реєстр, метадані IIS, база AD CS та інші системні файли та ресурси. Резервна копія створюється через службу тіньового копіювання VSS. \
`Get-WindowsFeature Windows-Server-Backup` перевірити чи встановлена роль \
`Add-Windowsfeature Windows-Server-Backup –Includeallsubfeature` встановити роль
```PowerShell
$path="\\$srv\bak-dc\dc-03\"
[string]$TargetUNC=$path+(get-date -f 'yyyy-MM-dd')
if ((Test-Path -Path $path) -eq $true) {New-Item -Path $TargetUNC -ItemType directory} # якщо шлях доступний, створити нову директорію за датою
$WBadmin_cmd = "wbadmin.exe START BACKUP -backupTarget:$TargetUNC -systemState -noverify -vssCopy -quiet"
# $WBadmin_cmd = "wbadmin start backup -backuptarget:$path -include:C:\Windows\NTDS\ntds.dit -quiet" # Backup DB NTDS
Invoke-Expression $WBadmin_cmd
````
### RDS
`Get-Command -Module RemoteDesktop` \
`Get-RDServer -ConnectionBroker $broker` список всіх серверів у фермі, вказується повне доменне ім'я при зверненні до сервера за участю RDCB \
`Get-RDRemoteDesktop -ConnectionBroker $broker` список колекцій \
`(Get-RDLicenseConfiguration -ConnectionBroker $broker | select *).LicenseServer` список серверів за участю RDL \
`Get-RDUserSession -ConnectionBroker $broker` список усіх активних користувачів \
`Disconnect-RDUser -HostServer $srv -UnifiedSessionID $id -Force` відключити сесію користувача \
`Get-RDAvailableApp -ConnectionBroker $broker -CollectionName C03` список встановлених програм на серверах в колекції \
`(Get-RDSessionCollectionConfiguration -ConnectionBroker $broker -CollectionName C03 | select *).CustomRdpProperty` use redirection server name:i:1 \
`Get-RDConnectionBrokerHighAvailability`

# DNSServer

`Get-Command -Module DnsServer` \
`Show-DnsServerCache` відобразити весь кеш DNS-сервера \
`Show-DnsServerCache | where HostName -match ru` \
`Clear-DnsServerCache` \
`Get-DnsServerCache` \
`Get-DnsServerDiagnostics`
```PowerShell
$zone = icm $srv {Get-DnsServerZone} | select ZoneName,ZoneType,DynamicUpdate,ReplicationScope,SecureSecondaries,
DirectoryPartitionName | Out-GridView -Title "DNS Server: $srv" -PassThru
$zone_name = $zone.ZoneName
if ($zone_name -ne $null) {
icm $srv {Get-DnsServerResourceRecord -ZoneName $using:zone_name | sort RecordType | select RecordType,HostName, @{
Label="IPAddress"; Expression={$_.RecordData.IPv4Address.IPAddressToString}},TimeToLive,Timestamp
} | select RecordType,HostName,IPAddress,TimeToLive,Timestamp | Out-GridView -Title "DNS Server: $srv"
}
````
`Sync-DnsServerZone –passthru` синхронізувати зони з іншими DC в домені \
`Remove-DnsServerZone -Name domain.local` видалити зону \
`Get-DnsServerResourceRecord -ZoneName domain.local -RRType A` вивести всі записи А в зазначеній зоні \
`Add-DnsServerResourceRecordA -Name new-host-name -IPv4Address 192.168.1.100 -ZoneName domain.local -TimeToLive 01:00:00 -CreatePtr` створити А-запис та PTR для неї \
`Remove-DnsServerResourceRecord -ZoneName domain.local -RRType A -Name new-host-name –Force` видалити А-запис
```PowerShell
$DNSServer = "DC-01"
$DNSFZone = "domain.com"
$DataFile = "C:\Scripts\DNS-Create-A-Records-from-File.csv"
# Cat $DataFile
# "HostName;IP"
# "server-01;192.168.1.10"
$DNSRR = [WmiClass]"\\$DNSServer\root\MicrosoftDNS:MicrosoftDNS_ResourceRecord"
$ConvFile = $DataFile + "_unicode"
Get-Content $DataFile | Set-Content $ConvFile -Encoding Unicode
Import-CSV $ConvFile -Delimiter ";" | ForEach-Object {
$FQDN = $_.HostName + "." + $DNSFZone
$IP = $_.HostIP
$TextA = "$FQDN IN A $IP"
[Void]$DNSRR.CreateInstanceFromTextRepresentation($DNSServer,$DNSFZone,$TextA)
}
````
# DHCPServer

`Get-Command -Module DhcpServer`
```PowerShell
$mac = icm $srv -ScriptBlock {Get-DhcpServerv4Scope | Get-DhcpServerv4Lease} | select AddressState,
HostName,IPAddress,ClientId,DnsRegistration,DnsRR,ScopeId,ServerIP | Out-GridView -Title "HDCP Server: $srv" -PassThru
(New-Object -ComObject Wscript.Shell).Popup($mac.ClientId,0,$mac.HostName,64)
````
`Add-DhcpServerv4Reservation -ScopeId 192.168.1.0 -IPAddress 192.168.1.10 -ClientId 00-50-56-C0-00-08 -Description "new reservation"`

# DFS

`dfsutil /root:\\domain.sys\public /export:C:\export-dfs.txt` експорт конфігурації namespace root \
`dfsutil /AddFtRoot /Server:\\$srv /Share:public` на новій машині попередньо створити корінь на основі домену \
`dfsutil /root:\\domain.sys\public /import:C:\export-dfs.txt /<verify /set` Import (перед імпортом даних у існуючий корінь DFS, утиліта створює резервну копію конфігурації кореня в поточному каталозі, з якого запускається утиліта dfsutil) \
`/verify` виводить зміни, які будуть внесені в процесі імпорту, без застосування \
`/set` змінює цільовий простір імен шляхом повного перезапису та заміни на конфігурацію простору імен з імпортованого файлу \
`/merge` імпортує конфігурацію простору імен на додаток до існуючої конфігурації для злиття, параметри файлу конфігурації будуть мати більший пріоритет, ніж існуючі параметри простору імен

`Export-DfsrClone` експортує клоновану базу даних реплікації DFS та параметри конфігурації тома \
`Get-DfsrCloneState` отримує стан операції клонування бази даних \
`Import-DfsrClone` імпортує клоновану базу даних реплікації DFS та параметри конфігурації тома

`net use x: \\$srv1\public\*` примонтувати диск \
`Get-DfsrFileHash x:\* | Out-File C:\$srv1.txt` забрати hash всіх файлів диска у файл (файли з однаковими хешами завжди є точними копіями один одного) \
`net use x: /d` відмонтувати \
`net use x: \\$srv2\public\*` \
`Get-DfsrFileHash x:\* | Out-File C:\$srv2.txt` \
`net use x: /d` \
`Compare-Object -ReferenceObject (Get-Content C:\$srv1.txt) -DifferenceObject (Get-Content C:\$srv2.txt) -IncludeEqual` порівняти вміст файлів

`Get-DfsrBacklog -DestinationComputerName "fs-06" -SourceComputerName "fs-05" -GroupName "folder-rep" -FolderName "folder" -Verbose` отримує список очікуваних оновлень файлів між двома партнерами реплікації DFS \
`Get-DfsrConnection` відображає групи реплікації, учасників та статус \
`Get-DfsReplicatedFolder` відображає ім'я та повний шлях до папок релікації в системі DFS \
`Get-DfsrState -ComputerName fs-06 -Verbose` стан реплікації DFS для члена групи \
`Get-DfsReplicationGroup` відображає групи реплікації та їх статус \
`Add-DfsrConnection` створює з'єднання між членами групи реплікації \
`Add-DfsrMember` додає комп'ютери до групи реплікації \
`ConvertFrom-DfsrGuid` перетворює ідентифікатори GUID на зрозумілі імена в заданій групі реплікації \
`Get-DfsrConnectionSchedule` отримує розклад з'єднань між членами групи реплікації \
`Get-DfsrGroupSchedule` отримує розклад групи реплікації \
`Get-DfsrIdRecord` отримує запис ID для реплікованих файлів або папок з бази даних реплікації DFS \
`Get-DfsrMember` отримує комп'ютери у групі реплікації \
`Get-DfsrMembership` отримує параметри членства для членів груп реплікації \
`Get-DfsrPreservedFiles` отримує список файлів та папок, раніше збережених реплікацією DFS \
`Get-DfsrServiceConfiguration` отримує параметри служби реплікації DFS для членів групи \
`Grant-DfsrDelegation` надає дозволи учасникам безпеки для групи реплікації \
`Revoke-DfsrDelegation` скасовує дозволи учасників безпеки для групи реплікації \
`New-DfsReplicationGroup` створює групу реплікації \
`New-DfsReplicatedFolder` створює репліковану папку в групі реплікації \
`Remove-DfsrConnection` видаляє з'єднання між членами групи реплікації \
`Remove-DfsReplicatedFolder` видаляє репліковану папку з групи реплікації \
`Remove-DfsReplicationGroup` видаляє групу реплікації \
`Remove-DfsrMember` видаляє комп'ютери з групи реплікації \
`Restore-DfsrPreservedFiles` відновлює файли та папки, раніше збережені реплікацією DFS \
`Set-DfsrConnection` змінює параметри з'єднання між членами групи реплікації \
`Set-DfsrConnectionSchedule` змінює параметри розкладу з'єднань між членами групи реплікації \
`Set-DfsReplicatedFolder` змінює налаштування реплікованої папки \
`Set-DfsReplicationGroup` змінює групу реплікації \
`Set-DfsrGroupSchedule` змінює розклад групи реплікації \
`Set-DfsrMember` змінює інформацію про комп'ютер-учасник у групі реплікації \
`Set-DfsrMembership` налаштовує параметри членства для членів групи реплікації \
`Set-DfsrServiceConfiguration` змінює параметри служби реплікації DFS \
`Sync-DfsReplicationGroup` синхронізує реплікацію між комп'ютерами незалежно від розкладу \
`Suspend-DfsReplicationGroup` призупиняє реплікацію між комп'ютерами незалежно від розкладу \
`Update-DfsrConfigurationFromAD` ініціює оновлення служби реплікації DFS \
`Write-DfsrHealthReport` створює звіт про працездатність реплікації DFS \
`Write-DfsrPropagationReport` створює звіти для тестових файлів розповсюдження в групі реплікації \
`Start-DfsrPropagationTest` створює тестовий файл розповсюдження в реплікованій папці

#StorageReplica

`Install-WindowsFeature Storage-Replica -IncludeManagementTools -Restart` \
`Get-Command -Module StorageReplica` \
`Test-SRTopology` перевірити чи відповідає сервер та канал зв'язку технології Storage Replica \
`New-SRPartnership -SourceComputerName srv-01 -SourceRGName srv-01-rep-group-01 -SourceVolumeName D: -SourceLogVolumeName L: -DestinationComputerName srv-02 -DestinationRGName srv-02-rep-group-01 L: -LogSizeInBytes 1GB` \
`Get-Counter -Counter "\Storage Replica Statistics(*)"` \
`Get-WinEvent -ProviderName Microsoft-Windows-StorageReplica -max 10` \
`Set-SRPartnership -ReplicationMode Asynchronous` переключити режим реплікації на асинхронний \
`Set-SRPartnership -NewSourceComputerName srv-02 -SourceRGName srv-02-rep-group-01 -DestinationComputerName srv-01 -DestinationRGName srv-01-rep-group-01` змінити вручну напрямок реплікації даних, перевівши вторинне при виході з ладу основного сервера)
`Get-SRGroup` інформація про стан групи реплізації \
`Get-SRPartnerShip` інформація про напрям реплікації \
`(Get-SRGroup).Replicas | Select-Object numofbytesremaining` перевірити довжину черги копіювання \
`Get-SRPartnership | Remove-SRPartnership` видалити реплізацію на основному сервері \
`Get-SRGroup | Remove-SRGroup` видалити реплізацію на обох серверах

# PS2EXE

`Install-Module ps2exe -Repository PSGallery` \
`Get-Module -ListAvailable` Список всіх модулів \
`-noConsole` використовувати GUI, без вікна консолі powershell \
`-noOutput` виконання у фоні \
`-noError` без виведення помилок \
`-requireAdmin` під час запуску запитати права адміністратора \
`-credentialGUI` виведення діалогового вікна для введення облікових даних \
`Invoke-ps2exe -inputFile "$home\Desktop\WinEvent-Viewer-1.1.ps1" -outputFile "$home\Desktop\WEV-1.1.exe" -iconFile "$home\Desktop\log_48px.ico" -title "WinEvent -Viewer" -noConsole -noOutput -noError`

# NSSM

`$powershell_Path = (Get-Command powershell).Source` \
`$NSSM_Path = (Get-Command "C:\WinPerf-Agent\NSSM-2.24.exe").Source` \
`$Script_Path = "C:\WinPerf-Agent\WinPerf-Agent-1.1.ps1"` \
`$Service_Name = "WinPerf-Agent"` \
`& $NSSM_Path install $Service_Name $powershell_Path -ExecutionPolicy Bypass -NoProfile -f $Script_Path` створити Service \
`& $NSSM_Path start $Service_Name` запустити \
`& $NSSM_Path status $Service_Name` статус \
`$Service_Name | Restart-Service` перезапустити \
`$Service_Name | Get-Service` статус \
`$Service_Name | Stop-Service` зупинити \
`& $NSSM_Path set $Service_Name description "Check performance CPU and report email"` змінити опис \
`& $NSSM_Path remove $Service_Name` видалити

# Jobs

`Get-Job` одержання списку завдань \
`Start-Job` запуск процесу \
`Stop-Job` зупинка процесу \
`Suspend-Job` припинення роботи процесу \
`Resume-Job` відновлення роботи процесу \
`Wait-Job` очікування на виведення команди \
`Receive-Job` одержання результатів виконаного процесу \
`Remove-Job` видалити завдання
```PowerShell
function Start-PingJob ($Network) {
$RNetwork = $Network -replace "\.\d{1,3}$","."
foreach ($4 in 1..254) {
$ip = $RNetwork+$4
# створюємо завдання, забираємо 3-й рядок виводу і додаємо до виводу ip-адресу:
(Start-Job {"$using:ip : "+(ping -n 1 -w 50 $using:ip)[2]}) | Out-Null
}
while ($ True) {
$status_job = (Get-Job).State[-1] # забираємо статус останнього завдання
if ($status_job -like "Completed"){ # перевіряємо на виконання (завдання виконуються по черзі зверху вниз)
$ ping_out = Get-Job | Receive-Job # якщо виконано, забираємо виведення всіх завдань
Get-Job | Remove-Job -Force # видаляємо завдання
$ping_out
break # завершуємо цикл
}}
}
````
`Start-PingJob -Network 192.168.3.0` \
`(Measure-Command {Start-PingJob -Network 192.168.3.0}).TotalSeconds` 60 Seconds

### ThreadJob

`Install-Module -Name ThreadJob` \
`Get-Module ThreadJob -list` \
`Start-ThreadJob {ping ya.ru} | Out-Null` створити фонове завдання \
Get-Job | Receive-Job -Keep` відобразити та не видаляти висновок \
`(Get-Job). HasMoreData` якщо False, то виведення комани видалено \
`(Get-Job)[-1].Output` відобразити висновок останнього завдання
```PowerShell
function Start-PingThread ($Network) {
$RNetwork = $Network -replace "\.\d{1,3}$","."
foreach ($4 in 1..254) {
$ip = $RNetwork+$4
# створюємо завдання, забираємо 3-й рядок виводу і додаємо до виводу ip-адресу:
(Start-ThreadJob {"$using:ip : "+(ping -n 1 -w 50 $using:ip)[2]}) | Out-Null
}
while ($ True) {
$status_job = (Get-Job).State[-1] # забираємо статус останнього завдання
if ($status_job -like "Completed"){ # перевіряємо на виконання (завдання виконуються по черзі зверху вниз)
$ ping_out = Get-Job | Receive-Job # якщо виконано, забираємо виведення всіх завдань
Get-Job | Remove-Job -Force # видаляємо завдання
$ping_out
break # завершуємо цикл
}}
}
````
`Start-PingThread -Network 192.168.3.0` \
`(Measure-Command {Start-PingThread -Network 192.168.3.0}).TotalSeconds` 24 Seconds

### PoshRSJob
```PowerShell
function Start-PingRSJob ($Network) {
$RNetwork = $Network -replace "\.\d{1,3}$","."
foreach ($4 in 1..254) {
$ip = $RNetwork+$4
(Start-RSJob {"$using:ip : "+(ping -n 1 -w 50 $using:ip)[2]}) | Out-Null
}
$ping_out = Get-RSJob | Receive-RSJob
$ping_out
Get-RSJob | Remove-RSJob
}
````
`Start-PingRSJob -Network 192.168.3.0` \
`(Measure-Command {Start-PingRSJob -Network 192.168.3.0}).TotalSeconds` 10 Seconds

# SMTP
```PowerShell
function Send-SMTP {
param (
[Parameter(Mandatory = $True)]$mess
)
$srv_smtp = "smtp.yandex.ru"
$port = "587"
$from = "login1@yandex.ru"
$to = "login2@yandex.ru"
$user = "login1"
$pass = "password"
$subject = "Service status on Host: $hostname"
$Message = New-Object System.Net.Mail.MailMessage
$Message.From = $from
$Message.To.Add($to)
$Message.Subject = $subject
$Message.IsBodyHTML = $true
$Message.Body = "<h1> $mess </h1>"
$smtp = New-Object Net.Mail.SmtpClient($srv_smtp, $port)
$smtp.EnableSSL = $true
$smtp.Credentials = New-Object System.Net.NetworkCredential($user, $pass);
$smtp.Send($Message)
}
````
`Send-SMTP $(Get-Service)`

# Hyper-V

`Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -Restart` встановити роль на Windows Server \
`Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All` встановити роль на Windows Desktop \
`Get-Command -Module hyper-v` \
`Get-VMHost`
```PowerShell
New-VMSwitch -name NAT -SwitchType Internal # створити віртуальний комутатор та адаптер для нього
Get-NetAdapter | where InterfaceDescription -match Hyper-V # список мережевих адаптерів
New-NetNat -Name LocalNat -InternalIPInterfaceAddressPrefix "192.168.3.0/24" # задати мережу
Get-NetAdapter "vEthernet (NAT)" | New-NetIPAddress -IPAddress 192.168.3.200 -AddressFamily IPv4 -PrefixLength 24 # присвоїти адресу, необхідно на ВМ вказати шлюз 192.168.3.200, щоб перебувати за NAT, або в налаштування ВМ вказати відповідний
Add-NetNatStaticMapping -NatName LocalNat -Protocol TCP -ExternalIPAddress 0.0.0.0 -ExternalPort 2222 -InternalIPAddress 192.168.3.103 -InternalPort 2121 # прокид, вест трафік який приходить на х2 вальної машини за NAT .
(Get-NetAdapter | where Name -match NAT).
````
`Get-NetNatStaticMapping` відобразити прокиди (NAT) \
`Get-NetNat` список мереж \
`Remove-NetNatStaticMapping -StaticMappingID 0` видалити прокид \
`Remove-NetNat -Name LocalNat` видалити мережу

`New-VMSwitch -Name Local -AllowManagementOS $True -NetAdapterName "Ethernet 4" -SwitchType External` створити вшений (External) віртуальний комутатор \
`$VMName = "hv-dc-01"`
```PowerShell
$VM = @{
Name = $VMName
MemoryStartupBytes = 4Gb
Generation = 2
NewVHDPath = "D:\VM\$VMName\$VMName.vhdx"
NewVHDSizeBytes = 50Gb
BootDevice = "VHD"
Path = "D:\VM\$VMName"
SwitchName = "NAT"
}
New-VM @VM
````
`Set-VMDvdDrive -VMName $VMName -Path "C:\Users\Lifailon\Documents\WS-2016.iso"` \
`New-VHD -Path "D:\VM\$VMName\disk_d.vhdx" -SizeBytes 10GB` створити VHDX диск \
`Add-VMHardDiskDrive -VMName $VMName -Path "D:\VM\$VMName\disk_d.vhdx"` вмонтувати диск \
`Get-VM -VMname $VMName | Set-VM –AutomaticStartAction Start` автозапуск \
`Get-VM -Name $VMName | Set-VMMemory -StartupBytes 8Gb`\
`Set-VMProcessor $VMName -Count 2` \
`Get-VM -Name $VMName | Checkpoint-VM -SnapshotName "Snapshot-1"`\
`Restore-VMCheckpoint -Name Snapshot-1" -VMName $VMName -Confirm:$false` \
Get-VM | Select -ExpandProperty NetworkAdapters | Select VMName,IPAddresses,Status` отримати IP адресу всіх ВМ \
`vmconnect.exe localhost $VMHost`

`Get-NetTCPConnection -State Established,Listen | Where-Object LocalPort -Match 2179` знайти порт слухача
`Get-Process -Id (Get-NetTCPConnection -State Established,Listen | Where-Object LocalPort -Match 2179).OwningProcess` знайти процес по ID (vmms/VMConnect) \
`New-NetFirewallRule -Name "Hyper-V" -DisplayName "Hyper-V" -Group "Hyper-V" -Direction Inbound -Protocol TCP -LocalPort 2179 -Action Allow -Profile Public` \
`Get-LocalGroupMember -Group "Адміністратори Hyper-V"` або "Hyper-V Administrators" \
`Add-LocalGroupMember -Group "Адміністратори Hyper-V" -Member "lifailon"` \
`Get-VM* | select name,ID` додати id до RDCMan для підключення \
`Grant-VMConnectAccess -ComputerName plex-01 -VMName hv-devops-01 -UserName lifailon` дати доступ на підключення не адміністратору \
`Grant-VMConnectAccess -ComputerName huawei-book -VMName hv-devops-01 -UserName lifailon` \
`Get-VMConnectAccess` \
`Revoke-VMConnectAccess -VMName hv-devops-01 -UserName lifailon`

Error: `Unknown disconnection reason 3848` - додати ключі реєстру на стороні клієнта
```PowerShell
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Credssp\PolicyDefaults\AllowFreshCredentialsDomain -Name Hyper-V -PropertyType String -Value "Microsoft Virtual Console Service/*" -Force
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Credssp\PolicyDefaults\AllowDefaultCredentials -Name Hyper-V -PropertyType String -Value "Microsoft Virtual Console Service/*" -Force
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Credssp\PolicyDefaults\AllowFreshCredentialsWhenNTLMOnlyDomain -Name Hyper-V -PropertyType String -Value "Microsoft Virtual Console Service/*" -Force
ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Credssp\PolicyDefaults\AllowDefaultCredentialsDomain -Name Hyper-V -PropertyType String -Value "Microsoft Virtual Console Service/*" -Force
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Credssp\PolicyDefaults\AllowFreshCredentials -Name Hyper-V -PropertyType String -Value "Microsoft Virtual Console Service/*" -Force
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Credssp\PolicyDefaults\AllowFreshCredentialsWhenNTLMOnly -Name Hyper-V -PropertyType String -Value "Microsoft Virtual Console Service/*" -Force
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Credssp\PolicyDefaults\AllowSavedCredentialsWhenNTLMOnly -Name Hyper-V -PropertyType String -Value "Microsoft Virtual Console Service/*" -Force
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Credssp\PolicyDefaults\AllowSavedCredentials -Name Hyper-V -PropertyType String -Value "Microsoft Virtual Console Service/*" -Force
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Credssp\PolicyDefaults\AllowSavedCredentialsDomain -Name Hyper-V -PropertyType String -Value "Microsoft Virtual Console Service/*" -Force
````
# VMWare/PowerCLI

`Install-Module -Name VMware.PowerCLI # -AllowClobber` встановити модуль (PackageProvider: nuget) \
`Get-Module -ListAvailable VMware* | Select Name,Version` \
`Import-Module VMware.VimAutomation.Core` імпортувати в сесію \
`Get-PSProvider | format-list Name,PSSnapIn,ModuleName` Список оснасток Windows PowerShell

`Get-PowerCLIConfiguration` конфігурація підключення \
`Set-PowerCLIConfiguration -Scope AllUsers -InvalidCertificateAction ignore -confirm:$false` якщо використовується самопідписаний сертифікат, змінити значення параметра InvalidCertificateAction з Unset на Ignore/Warn \
`Set-PowerCLIConfiguration -Scope AllUsers -ParticipateInCeip $false` відключити повідомлення збору даних через VMware Customer Experience Improvement Program (CEIP)

`Read-Host –AsSecureString | ConvertFrom-SecureString | Out-File "$home\Documents\vcsa_password.txt"` зашифрувати пароль та зберегти у файл \
`$esxi = "vcsa.domain.local"` \
`$user = "administrator@vsphere.local"` \
`$pass = Get-Content "$home\Documents\vcsa_password.txt" | ConvertTo-SecureString` прочитати пароль \
`$pass = "password"` \
`$Cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user ,$pass` \
`Connect-VIServer $esxi -User $Cred.Username -Password $Cred.GetNetworkCredential().password` підключитися, використовуючи PSCredential ($Cred) \
`Connect-VIServer $esxi -User $user -Password $pass` підключитися, використовуючи логін та пароль

`Get-Command –Module *vmware*` \
`Get-Command –Module *vmware* -name *get*iscsi*` \
`Get-IScsiHbaTarget` \
`Get-Datacenter` \
`Get-Cluster` \
`Get-VMHost` \
`Get-VMHost | select Name,Model,ProcessorType,MaxEVCMode,NumCpu,CpuTotalMhz,CpuUsageMhz,MemoryTotalGB,MemoryUsageGB` \
`Get-VMHostDisk | select VMHost,ScsiLun,TotalSectors`

`Get-Datastore` \
`Get-Datastore TNAS-vmfs-4tb-01` \
`Get-Datastore TNAS-vmfs-4tb-01 | get-vm`\
`Get-Datastore -RelatedObject vm-01` \
`(Get-Datastore TNAS-vmfs-4tb-01).ExtensionData.Info.GetType()` \
`(Get-Datastore TNAS-vmfs-4tb-01).ExtensionData.Info.Vmfs.Extent`

`Get-Command –Module *vmware* -name *disk*` \
`Get-VM vm-01 | Get-Datastore`\
`Get-VM vm-01 | Get-HardDisk`\
Get-VM | Get-HardDisk | select Parent,Name,CapacityGB,StorageFormat,FileName | ft` \
`Copy-HardDisk` \
Get-VM | Get-Snapshot`\
Get-VM | where {$_.Powerstate -eq "PoweredOn"}` \
`Get-VMHost esxi-05 | Get-VM | where {$_.Powerstate -eq "PoweredOff"} | Move-VM –Destination (Get-VMHost esxi-06)`

Get-VM | select Name,VMHost,PowerState,NumCpu,MemoryGB,` \
`@{Name="UsedSpaceGB"; Expression={[int32]($_.UsedSpaceGB)}},@{Name="ProvisionedSpaceGB"; Expression={[int32]($_.ProvisionedSpaceGB)}},` \
`CreateDate,CpuHotAddEnabled,MemoryHotAddEnabled,CpuHotRemoveEnabled,Notes`

`Get-VMGuest vm-01 | Update-Tools`\
`Get-VMGuest vm-01 | select OSFullName,IPAddress,HostName,State,Disks,Nics,ToolsVersion` \
`Get-VMGuest* | select -ExpandProperty IPAddress` \
`Restart-VMGuest -vm vm-01 -Confirm:$False` \
`Start-VM -vm vm-01 -Confirm:$False` \
`Shutdown-VMGuest -vm vm-01 -Confirm:$false`

`New-VM -Name vm-01 -VMHost esxi-06 -ResourcePool Production -DiskGB 60 -DiskStorageFormat Thin -Datastore TNAS-vmfs-4tb-01` \
`Get-VM vm-01 | Copy-VMGuestFile -Source "\$srv\Install\Soft\Btest.exe" -Destination "C:\Install\" -LocalToGuest -GuestUser USER -GuestPassword PASS -force`

`Get-VM-name vm-01 | Export-VApp -Destination C:\Install -Format OVF` Export template (.ovf, .vmdk, .mf) \
`Get-VM-name vm-01 | Export-VApp -Destination C:\Install -Format OVA`

`Get-VMHostNetworkAdapter | select VMHost,Name,Mac,IP,@{Label="Port Group"; Expression={$_.ExtensionData.Portgroup}} | ft` \
Get-VM | Get-NetworkAdapter | select Parent,Name,Id,Type,MacAddress,ConnectionState,WakeOnLanEnabled | ft`

`Get-Command –Module *vmware* -name *event*` \
`Get-VIEvent-MaxSamples 1000 | where {($_.FullFormattedMessage -match "power")} | select username,CreatedTime,FullFormattedMessage` \
`Get-logtype | select Key,SourceEntityId,Filename,Creator,Info` \
`(Get-Log vpxd:vpxd.log).Entries | select -Last 50`

`Get-Command –Module *vmware* -name *syslog*` \
`Set-VMHostSysLogServer -VMHost esxi-05 -SysLogServer "tcp://192.168.3.100" -SysLogServerPort 3515` \
`Get-VMHostSysLogServer -VMHost esxi-05`

# Exchange/EMShell

`$srv_cas = "exchange-cas"` \
`$session_exchange = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$srv_cas/PowerShell/` -Credential $Cred -Authentication Kerberos \
`Get-PSSession` \
`Import-PSSession $session_exchange -DisableNameChecking` імпортувати у поточну сесію

`Get-ExchangeServer | select name,serverrole,admindisplayversion,Edition,OriginatingServer,WhenCreated,WhenChanged,DataPath | ft` список усіх серверів

`Get-ImapSettings` налаштування IMAP \
`Get-ExchangeCertificate` список сертифікатів \
`Get-ExchangeCertificate -Thumbprint "5CEC8544D4743BC279E5FEA1679F79F5BD0C2B3A" | Enable-ExchangeCertificate -Services IMAP, POP, IIS, SMTP`\
`iisreset` \
`Get-ClientAccessService | fl identity, *uri*` налаштування служби автовиявлення в Exchange 2016 \
`Get-ClientAccessService -Identity $srv | Set-ClientAccessService -AutoDiscoverServiceInternalUri https://mail.domain.ru/Autodiscover/Autodiscover.xml` змінити на зовнішню адресу \
`Get-OutlookAnywhere` OA дозволяє клієнтам Outlook підключатися до своїх поштових скриньок за межами локальної мережі (без використання VPN) \
`Get-WebServicesVirtualDirectory` \
`Get-OwaVirtualDirectory` \
`Get-ActiveSyncVirtualDirectory` \
`Get-OabVirtualDirectory` віртуальна директорія автономної адресної книги \
`Get-OabVirtualDirectory -Server $srv | Set-OabVirtualDirectory -InternalUrl "https://mail.domain.ru/OAB" -ExternalUrl "https://mail.domain.ru/OAB"`

### Roles
MS (Mailbox) - сервер із БД поштових скриньок та спільних папок, відповідає лише за їх розміщення та не виконує маршрутизацію жодних повідомлень. \
CAS (Client Access Server) – обробка клієнтських підключень до поштових скриньок, які створюються клієнтами Outlook Web Access (HTTP для Outlook Web App), Outlook Anywhere, ActiveSync (для мобільних пристроїв), інтернет протоколи POP3 та IMAP4, MAPI для клієнтів Microsoft Outlook. \
Hub Transort відповідає за маршрутизацію повідомлень інтернету та інфраструктурою Exchange, а також між серверами Exchange. Повідомлення завжди маршрутизуються за допомогою ролі транспортного сервера-концентратора, навіть якщо поштові скриньки джерела та призначення знаходяться в одній базі даних поштових скриньок. \
Relay – роль прикордонного транспортного сервера (шлюз SMTP у периметрі мережі).

SCP (Service Connection Point) - запис прописується в AD, створюючи сервер CAS. Outlook запитує SCP, вибирає ті, які знаходяться в одному сайті з ним і за параметром WhenCreated – за датою створення, вибираючи найстаріший. \
Autodiscover. Outlook вибирає як сервер Client Access той, який прописаний в атрибуті RPCClientAccessServer бази даних користувача. Відомості про базу даних та сервер mailbox, на якому вона лежить, беруться з AD.

### MessageTrackingLog
`Get-MessageTrackingLog -ResultSize Unlimited | select Timestamp,Sender,Recipients,RecipientCount,MessageSubject,Source,EventID,ClientHostname,ServerHostname,ConnectorId, @{Name="MessageSize"; Expression={[string]([int]($_.TotalBytes / 1024))+" KB"}},@{Name="MessageLatency"; Expression={$_.MessageLatency -replace "\.\d+$"}}` \
`Get-MessageTrackingLog -Start (Get-Date).AddHours(-24) -ResultSize Unlimited | where {[string]$_.recipients -like "*@yandex.ru"}` вивести повідомлення за останні 24 години, де одержувачем був зазначений домен \
-Start "04/01/2023 09:00:00" -End "04/01/2023 18:00:00" - пошук за вказаним проміжком часу \
-MessageSubject "Тест" - пошук на тему листа \
-Recipients "support4@domain.ru" - пошук по одержувачу \
-Sender - пошук по відправнику \
-EventID – пошук за кодом події сервера (RECEIVE, SEND, FAIL, DSN, DELIVER, BADMAIL, RESOLVE, EXPAND, REDIRECT, TRANSFER, SUBMIT, POISONMESSAGE, DEFER) \
-Server – пошук на певному транспортному сервері \
-messageID – трекінг листа за його ID

### Mailbox
`Get-Mailbox -Database "it2"` список поштових серверів у базі даних \
`Get-Mailbox -resultsize unlimited | ? Emailaddresses -like "support4" | format-list name,emailaddresses,database,servername` яку БД, сервер та smtp-адреси використовує поштову скриньку \
`Get-Mailbox -Database $db_name -Archive` відобразити архівні поштові скриньки

`Get-MailboxFolderStatistics -Identity "support4" -FolderScope All | select Name,ItemsInFolder,FolderSize` відобразити кількість листів і розмір у кожній папці \
`Get-MailboxStatistics "support4" | select DisplayName,LastLoggedOnUserAccount,LastLogonTime,LastLogoffTime,ItemCount,TotalItemSize,DeletedItemCount,TotalDeletedItemSize,Database,ServerName` загальна кількість листів, їх розмір, час останнього входу і виходу, ім'я сервера
`Get-Mailbox-Server s2 | Get-MailboxStatistics | where {$_.Lastlogontime -lt (get-date).AddDays(-30)} | Sort Lastlogontime-desc | ft displayname,Lastlogontime,totalitemsize` ящики, які не використовувалися 30 і більше днів

`Enable-Mailbox -Identity support9 -Database test_base` створити поштову скриньку для існуючого користувача в AD \
`New-Mailbox -Name $login -UserPrincipalName "$login@$domain" -Database $select_db -OrganizationalUnit $path -Password (ConvertTo-SecureString -String "$password" -AsPlainText -Force)` створити нову поштову скриньку без прив'язки до користувачу AD \
`Get-MailboxDatabase -Database $db_name | Remove-MailboxDatabase` видалити БД

`Set-MailBox "support4" -PrimarySmtpAddress support24@domain.ru -EmailAddressPolicyEnabled $false` додати та змінити основну SMTP-адресу електронної пошти для користувача \
`Set-Mailbox -Identity "support4" -DeliverToMailboxAndForward $true -ForwardingSMTPAddress "username@outlook.com"` включити переадресацію пошти (електронна пошта потрапляє до поштової скриньки користувача support4 і одночасно пересилається на адресу username@outlook.com)

### MoveRequest
`Get-Mailbox -Database $db_in | New-MoveRequest -TargetDatabase $db_out` перемістити всі поштові скриньки з однієї БД до іншої \
`New-MoveRequest -Identity $db_in -TargetDatabase $db_out` перемістити одну поштову скриньку \
`Get-MoveRequest | Suspend-MoveRequest` зупинити запити переміщення \
`Get-MoveRequest | Remove-MoveRequest` видалити запити на переміщення \
`Get-MoveRequest | Get-MoveRequestStatistics` статус переміщення

Status: \
Cleanup - потрібно почекати
Queued - у черзі \
InProgress - у процесі \
Percent Complete - процент виконання \
CompletionInProgress - завершення процесу \
Completed - завершено

`Remove-MoveRequest -Identity $db_name` завершити процес переміщення (прибрати статус переміщення з поштової скриньки та очистити список переміщень) \
`Get-MailboxDatabase | Select Name, MailboxRetention` після переміщення ящиків, розмір бази не зміниться, повне видалення з бази відбудеться, як мине кількість днів, виставлену в параметрі MailboxRetention \
`Set-MailboxDatabase -MailboxRetention '0.00:00:00' -Identity $db_name` змінити значення

### Archive
`Enable-Mailbox -Identity $name -Archive` включити архів для користувача \
`Get-Mailbox $name | New-MoveReques –ArchiveOnly –ArchiveTargetDatabase DBArch` перемістити архівну поштову скриньку в іншу БД \
`Get-Mailbox $name | fl Name,Database,ArchiveDatabase` місце розташування БД користувача та БД його архіву \
`Disable-Mailbox -Identity $name -Archive` відключити архів \
`Connect-Mailbox -Identity "8734c04e-981e-4ccf-a547-1c1ac7ebf3e2" -Archive -User $name -Database it2` підключення архіву користувача до вказаної поштової скриньки \
`Get-Mailbox $name | Set-Mailbox -ArchiveQuota 20GB -ArchiveWarningQuota 19GB` налаштувати квоти зберігання архіву

### Quota
`Get-Mailbox -Identity $mailbox | fl IssueWarningQuota, ProhibitSendQuota, ProhibitSendReceiveQuota, UseDatabaseQuotaDefaults` відобразити квоти поштової скриньки \
IssueWarningQuota - квота, при досягненні якої Exchange надішле повідомлення \
ProhibitSendQuota - при досягненні буде заборонено відправлення \
ProhibitSendReceiveQuota - при досягненні буде заборонено відправлення та отримання \
UseDatabaseQuotaDefaults - чи використовується квота БД або false - індивідуальні \
`Set-Mailbox -Identity $mailbox -UseDatabaseQuotaDefaults $false -IssueWarningQuota "3 GB" -ProhibitSendQuota "4 GB" -ProhibitSendReceiveQuota "5 GB"` задати квоту для користувача

`Get-MailboxDatabase $db_name | fl Name, *Quota` відобразити квоти накладені на БД \
`Set-MailboxDatabase $db -ProhibitSendReceiveQuota "5 GB" -ProhibitSendQuota "4 GB" -IssueWarningQuota "3 GB"` налаштувати квоти на БД

### Database
`Get-MailboxDatabase-Status | select ServerName,Name,DatabaseSize` список та розмір всіх БД на всіх MX-серверах \
`New-MailboxDatabase -Name it_2022 -EdbFilePath E:\Bases\it_2022\it_2022.edb -LogFolderPath G:\Logs\it_2022 -OfflineAddressBook "Default Offline Address List" -server exch-mx
`Restart-Service MSExchangeIS` \
Get-Service | Where {$_ -match "exchange"} | Restart-Service`\
`Get-MailboxDatabase -Server exch-01` список баз даних на MX-сервері \
`New-MoveRequest -Identity "support4" -TargetDatabase it_2022` перемістити поштову скриньку в нову БД \
`Move-Databasepath $db_name –EdbFilepath "F:\DB\$db_name\$db_name.edb" –LogFolderpath "E:\DB\$db_name\logs\"` перемістити БД та транзакційні логи на інший диск \
`Set-MailboxDatabase -CircularLoggingEnabled $true -Identity $db_name` включити циклічне ведення журналу (Circular Logging), де послідовно пишуться 4 файли логів по 5 МБ, після чого перший лог-файл перезаписується \
`Set-MailboxDatabase -CircularLoggingEnabled $false -Identity $db_name` відключити циклічне ведення журналу \
`Get-MailboxDatabase -Server "exch-mx-01" -Status | select EdbFilePath,LogFolderPath,LogFilePrefix` шлях до БД, логів, ім'я поточного актуального лог-файлу

### MailboxRepairRequest
`New-MailboxRepairRequest -Database it2 -CorruptionType ProvisionedFolder, SearchFolder, AggregateCounts, Folderview` запустити послідовний тест (у конкретний момент часу не доступна одна поштова скринька) та виправлення помилок на прикладному рівні \
`Get-MailboxRepairRequest -Database it2` прогрес виконання \
Дозволяє виправити: \
ProvisionedFolder – порушення логічної структури папок \
SearchFolder – помилки в папках пошуку \
AggregateCounts – перевірка та виправлення інформації про кількість елементів у папках та їх розмір \
FolderView – неправильний вміст, що відображається уявленнями папок

### eseutil
При надсиланні/отриманні будь-якого листа Exchange спочатку вносить інформацію в транзакційний лог, і лише потім зберігає елемент безпосередньо до бази даних. Розмір одного лог файлу – 1 Мб. Існують три способи урізання логів: DAG, Backup на базі Volume Shadow Copy, Circular Logging.

Ручне видалення журналів транзакцій: \
`cd E:\MS_Exchange_2010\MailBox\Reg_v1_MailBoxes\` перейти до каталогу з логами \
`ls E*.chk` дізнатися ім'я файлу, в якому знаходиться інформація з контрольної точки фіксації журналів \
`eseutil /mk .\E18.chk` дізнатися останній файл журналу, дії з якого були занесені до БД Exchange \
`Checkpoint: (0x561299,8,16)` 561299 ім'я файлу, який був останнім зафіксований (його інформація вже в базі даних) \
Знаходимо у провіднику файл E0500561299.txt, можна видаляти всі файли журналів, які старші за знайдений файл

Відновлення БД (якщо дві копії БД помилково): \
`Get-MailboxDatabaseCopyStatus -Identity db_name\* | Format-List Name,Status,ContentIndexState` \
Status : FailedAndSuspended \
ContentIndexState : Failed \
Status: Dismounted \
ContentIndexState : Failed

`Get-MailboxDatabase -Server exch-mx-01 -Status | fl Name,EdbFilePath,LogFolderPath` перевірити розташування бази та транзакційних логів \
LogFolderPath - директорія логів \
E18 - ім'я транкзакційного лога (з нього читаються решта логів) \
`dismount-Database db_name` відмонтувати БД \
`eseutil /mh D:\MS_Exchange_2010\Mailbox\db_name\db_name.edb` перевірити базу \
State: Dirty Shutdown - неузгоджений стан, означає, що частина транзакцій не перенесена до бази, наприклад, після того, як було здійснено аварійне перезавантаження сервера. \
`eseutil /ml E:\MS_Exchange_2010\MailBox\db_name\E18` перевірка цілісності транзакційних логи, якщо є логи транзакцій і вони не зіпсовані, то можна відновити з них, з файлу E18 зчитуються всі логи, повинен бути статус - ОК

Soft Recovery (м'яке відновлення) - необхідно перевести базу в стан коректного відключення (Clear shutdown) шляхом запису відсутніх файлів журналів транзакцій у БД. \
`eseutil /R E18 /l E:\MS_Exchange_2010\MailBox\db_name\ /d D:\MS_Exchange_2010\Mailbox\db_name\db_name.edb` \
`eseutil /R E18 /a /i /l E:\MS_Exchange_2010\MailBox\db_name\ /d D:\MS_Exchange_2010\Mailbox\db_name\db_name.edb` якщо з логами щось не так, можна спробувати відновити базу ігноруючи помилку у логах \
`eseutil /mk D:\MS_Exchange_2010\Mailbox\db_name\db_name.edb` стану файлу контрольних точок \
`eseutil /g D:\MS_Exchange_2010\Mailbox\db_name\db_name.edb` перевірка цілісності БД \
`eseutil /k D:\MS_Exchange_2010\Mailbox\db_name\db_name.edb` перевірка контрольних сум бази (CRC)

Hard Recovery - якщо логи містять помилки та база не відновлюється, то відновлюємо базу без логів. \
`eseutil /p D:\MS_Exchange_2010\Mailbox\db_name\db_name.edb` \
/p - видалить пошкоджені сторінки, ця інформація буде видалена з БД і відновить цілісність \
`esetuil /d D:\MS_Exchange_2010\Mailbox\db_name\db_name.edb` виконати дефрагментацію (якщо було втрачено великий обсяг даних, то може сильно знизитися продуктивність) \
Після виконання команд необхідно вручну видалити всі файли з розширенням log у папці MDBDATA перед спробою змонтувати базу даних. \
`isinteg -s "db_name.edb" -test alltests` перевірте цілісність бази даних \
`isinteg -s "server_name" -fix -test -alltests` якщо перевірка буде провалена. Виконувати команду до тих пір, поки у всіх помилок не стане статус 0 або статус не перестане змінюватися, іноді необхідно 3 проходи для досягнення результату. \
`eseutil /mh D:\MS_Exchange_2010\Mailbox\db_name\db_name.edb | Select-String -Pattern "State:","Log Required:"` перевірити статус \
State: Clear shutdown - успішний статус \
`Log Required` потрібні файли журналів, необхідні базі, щоб перейти в узгоджений стан. Якщо база розмонтована коректно, це значення дорівнюватиме 0. \
`mount-Database -force db_name` примонтувати БД \
`Get-MailboxDatabase -Status db_name | fl Mounted` статус БД \
`New-MailboxRepairRequest -Database db_name -CorruptionType SearchFolder,AggregateCounts,ProvisionedFolder,FolderView` відновлення логічної цілісності даних \
Після цього відновити Index. \
Якщо індекси не відновлюються, але БД монтується, перенести поштові скриньки в нову БД.

Відновлення БД із Backup:

1-й варіант:
1. Відмонтувати поточну БД та видалити або перейменувати директорію з файлами поточної БД.
3. Відновити в ту ж директорію з Backup бази з логами.
4. Запустити м'яке відновлення БД (Soft Recovery).
5. Примоніторувати.

2-й варіант:
1. Відмонтувати та видалити поточну БД.
2. Відновити БД з логами із Backup у будь-яке місце.
3. Запустити м'яке відновлення БД (Soft Recovery).
4. Створити нову БД.
5. Створити Recovery Database та змонтувати в неї відновлену з бекапу БД, скопіювати з неї поштові скриньки в нову БД та переключити на них користувачів.
6. Якщо використовувати Dial Tone Recovery, то також перенести з тимчасової БД проміжні дані поштових скриньок.

3-й варіант:
1. Відновити цілісність Soft Repair або Hard Recovery.
2. Створити нову БД. Вказувати у властивостях: "база може бути перезаписана при відновленні".
3. Якщо база була щойно створена і ще не була підмонтована, то ця папка буде порожня, туди переміщуємо базу з Backup, яка була оброблена ESEUTIL разом з усіма файлами. Вказати ім'я .edb таке саме, яке було при створенні нової бази.
4. Монтуємо базу.
5. Перенацілюємо ящики зі старої (Mailbox_DB_02), несправної бази, на нову базу (Mailbox_DB_02_02):
`Get-Mailbox -Database Mailbox_DB_02 | where {$_.ObjectClass -NotMatch '(SystemAttendantMailbox|ExOleDbSystemMailbox)'} | Set-Mailbox -Database Mailbox_DB_02_02`
6. Відновлення логічної цілісності даних:
`New-MailboxRepairRequest -Database "Mailbox_DB_02_02" -CorruptionType ProvisionedFolder, SearchFolder, AggregateCounts, Folderview`

### Dial Tone Recovery
`Get-Mailbox-Database "MailboxDB" | Set-Mailbox -Database "TempDB"` перенацілити ящики з однієї БД (неробочої) на іншу (порожню) \
`Get-Mailbox -Database TempDB` відобразити поштові скриньки в БД TempDB \
`Restart-Service MSExchangeIS` перезапустити службу Mailbox Information Store (банку даних), інакше користувачі, як і раніше, намагатимуться підключитися до старої БД \
`iisreset` \
`Get-Mailbox-Database "TempDB" | Set-Mailbox -Database "MailboxDB"` після відновлення старої БД, потрібно переключити користувачів з тимчасової БД назад \
Після цього зробити злиття з тимчасовою БД за допомогою Recovery.

### Recovery database (RDB)
`New-MailboxDatabase -Recovery -Name RecoveryDB -Server $exch_mx -EdbFilePath "D:\TempDB\TempDB.edb" -LogFolderPath "D:\TempDB"` для перенесення нових листів з тимчасової БД в основну необхідний тільки сам файл TempDB.edb зі статусом Clean Shutdown, з неї необхідно створити службову БД (ключ-Recovery)
`Mount-Database "D:\TempDB\TempDB.edb"` примонтувати БД \
`Get-MailboxStatistics -Database RecoveryDB` \
`New-MailboxRestoreRequest –SourceDatabase RecoveryDB –SourceStoreMailbox support –TargetMailbox support` скопіювати дані поштової скриньки з DisplayName: support з RecoveryDB до поштової скриньки з псевдонімом support існуючої бази. За промовчанням шукає в поштовій базі збігаються LegacyExchangeDN або перевіряє збіг адреси X500, якщо потрібно відновити дані в іншу скриньку, потрібно вказувати ключ -AllowLegacyDNMisMatch \
`New-MailboxRestoreRequest –SourceDatabase RecoveryDB –SourceStoreMailbox support –TargetMailbox support –TargetRootFolder "Restore"` скопіювати листи в окрему папку в скриньці призначення (створюється автоматично), можна відновити вміст конкретної папки - "##Inbox
`Get-MailboxRestoreRequest | Get-MailboxRestoreRequestStatistics` статус запиту відновлення \
`Get-MailboxRestoreRequestStatistics -Identity support` \
`Get-MailboxRestoreRequest -Status Completed | Remove-MailboxRestoreRequest` видалити усі успішні запити

### Transport
`Get-TransportServer $srv_cas | select MaxConcurrentMailboxDeliveries,MaxConcurrentMailboxSubmissions,MaxConnectionRatePerMinute,MaxOutboundConnections,MaxPerDomainOutboundConnections,PickupDirectoryMaxMessagesPerMinute` налаштування пропускної спроможності транспортного сервера \
MaxConcurrentMailboxDeliveries — максимальна кількість одночасних потоків, яка може відкрити сервер для надсилання листів. \
MaxConcurrentMailboxSubmissions — максимальна кількість одночасних потоків, які можуть відкрити сервер для отримання листів. \
MaxConnectionRatePerMinute — максимальна можлива швидкість відкриття вхідних з'єднань за хвилину. \
MaxOutboundConnections — максимальна кількість з'єднань, які можна відкрити для відправлення Exchange. \
MaxPerDomainOutboundConnections — максимальна кількість вихідних з'єднань, яка може відкрити Exchange для одного віддаленого домену. \
PickupDirectoryMaxMessagesPerMinute — швидкість внутрішньої обробки повідомлень за хвилину (розподіл листів по папках). \
`Set-TransportServer exchange-cas -MaxConcurrentMailboxDeliveries 21 -MaxConcurrentMailboxSubmissions 21 -MaxConnectionRatePerMinute 1201 -MaxOutboundConnections 1001 -MaxPerDomainOutboundConnections 21 -PickupDirectoryMaxMessa0

`Get-TransportConfig | select MaxSendSize, MaxReceiveSize` обмеження розміру повідомлення на рівні транспорту (найменший пріоритет, після конектора та поштової скриньки). \
`New-TransportRule -Name AttachmentLimit -AttachmentSizeOver 15MB -RejectMessageReasonText "Сорри, повідомлення з даними над 15 MB не є придатними"` створити транспортне правило для перевірки розміру вкладення

### Connector
`Get-ReceiveConnector | select Name,MaxMessageSize,RemoteIPRanges,WhenChanged` обмеження розміру повідомлення на рівні конектора (пріоритет нижче, ніж у поштової скриньки) \
`Set-ReceiveConnector ((Get-ReceiveConnector).Identity)[-1] -MaxMessageSize 30Mb` змінити розмір у останнього конектора в списку (пріоритет вище, ніж у транспорту) \
`Get-Mailbox "support4" | select MaxSendSize, MaxReceiveSize` найвищий пріоритет \
`Set-Mailbox "support4" -MaxSendSize 30MB -MaxReceiveSize 30MB` змінити розмір

`Set-SendConnector -Identity "ConnectorName" -Port 26` змінити порт конектора відправки \
`Get-SendConnector "proxmox" | select port`

`Get-ReceiveConnector | select Name,MaxRecipientsPerMessage` за промовчанням Exchange приймає обмежену кількість адресатів в одному листі (200) \
`Set-ReceiveConnector ((Get-ReceiveConnector).Identity)[-1] -MaxRecipientsPerMessage 50` змінити значення \
`Set-ReceiveConnector ((Get-ReceiveConnector).Identity)[-1] -MessageRateLimit 1000` задати ліміт обробки повідомлень за хвилину для конектора

`Get-OfflineAddressbook | Update-OfflineAddressbook` оновити OAB \
`Get-ClientAccessServer | Update-FileDistributionService`

### PST
`New-MailboxExportRequest -Mailbox $name -filepath "\\$srv\pst\$name.PST" # -ContentFilter {(Received -lt "01/01/2021")} -Priority Highest/Lower # -IsArchive` виконати експорт з архіву користувача \
`New-MailboxExportRequest -Mailbox $name -IncludeFolders "#Inbox#" -FilePath "\\$srv\pst\$name.PST"` тільки папку вхідні \
`New-MailboxImportRequest -Mailbox $name "\\$srv\pst\$name.PST"` імпорт з PST \
`Get-MailboxExportRequest` статус запитів \
`Get-MailboxExportRequest -Status Completed | Remove-MailboxExportRequest` видалити успішно завершені запити \
`Remove-MailboxExportRequest -RequestQueue MBXDB01 -RequestGuid 25e0eaf2-6cc2-4353-b83e-5cb7b72d441f` скасувати експорт

### DistributionGroup
`Get-DistributionGroup` список груп розсилки \
`Get-DistributionGroupMember "!_Офіс"` список користувачів в групі \
`Add-DistributionGroupMember -Identity "!_Офіс" -Member "$name@$domain"` додати до групи розсилки \
`Remove-DistributionGroupMember -Identity "!_Офіс" -Member "$name@$domain"` \
`New-DistributionGroup -Name "!_Тест" -Members "$name@$domain"` створити групу \
`Set-DistributionGroup -Identity "support4" -HiddenFromAddressListsEnabled $true (або Set-Mailbox)` приховати зі списку адрес Exchange

### Search
`Search-Mailbox -Identity "support4" -SearchQuery 'Тема:"Mikrotik DOWN"'` пошук листів на тему \
`Search-Mailbox -Identity "support4" -SearchQuery 'Subject:"Mikrotik DOWN"'``\
`Search-Mailbox -Identity "support4" -SearchQuery 'attachment -like:"*.rar"'`\
`Search-Mailbox -Identity "support4" -SearchQuery "відправлено: < 01/01/2020" -DeleteContent -Force` видалення листів за датою

Формат дати в залежності від регіональних налаштувань сервера: \
`20/07/2018` \
`07/20/2018` \
`20-Jul-2018` \
`20/July/2018`

### AuditLog
`Get-AdminAuditLogConfig` налаштування аудиту \
`Set-Mailbox -Identity "support4" -AuditOwner HardDelete` додати логування HardDelete листів \
`Set-mailbox -identity "support4" -AuditlogAgelimit 120` вказати час зберігання \
`Get-mailbox-identity "support4" | Format-list Audit*` дані аудиту \
`Search-MailboxAuditLog -Identity "support4" -LogonTypes Delegate -ShowDetails -Start "2022-02-22 18:00" -End "2022-03-22 18:00"` перегляд логів \
`Search-AdminAuditLog -StartDate "02/20/2022" | ft CmdLetName,Caller,RunDate,ObjectModified -Autosize` пошук подій історії виконаних команд у журналі аудиту Exchange

### Test
`Test-ServiceHealth` перевірити доступність ролей сервера: поштових скриньок, клієнтського доступу, єдиної системи обміну повідомленнями, транспортного сервера \
`$mx_srv_list | %{Test-MapiConnectivity -Server $_}` перевірка підключення MX-серверів до БД \
`Test-MAPIConnectivity -Database $db` перевірка можливості логіну в базу \
`Test-MAPIConnectivity –Identity $user@$domain` перевірка можливості логіну в поштову скриньку \
`Test-ComputerSecureChannel` перевірка роботи служби AD \
`Test-MailFlow` результат тестового потоку пошти

### Queue
`Get-TransportServer | %{Get-Queue -Server $_.Name}` відобразити черги на всіх транспортних серверах \
`Get-Queue-Identity EXCHANGE-CAS\155530 | Format-List` детальна інформація про чергу \
`Get-Queue-Identity EXCHANGE-CAS\155530 | Get-Message -ResultSize Unlimited | Select FromAddress,Recipients` відобразити список відправників (FromAddress) та список одержувачів у черзі (Recipients) \
`Get-Message -Queue EXCHANGE-CAS\155530` відобразити ідентифікатор повідомлень у конкретній черзі (сервер\черга\ідентифікатор письма) \
`Resume-Message EXCHANGE-CAS\155530\444010` повторити відправку листа з черги \
`Retry-Queue -Filter {Status -eq "Retry"}` примусово повторити відправку всіх повідомлень зі статусом "Повторити" \
`Get-Queue-Identity EXCHANGE-CAS\155530 | Get-Message -ResultSize unlimited | Remove-Message -WithNDR $False` очистити чергу \
`Get-transportserver EXCHANGE-CAS | Select MessageExpirationTimeout` відобразити час життя повідомлень у черзі (за замовчуванням, 2 дні)

Error Exchange 452 4.3.1 Insufficient system resources - закінчення вільного місця на диску, на якому знаходяться черги служби Exchange Hub Transport, за моніторинг відповідає компонент доступних ресурсів Back Pressure, який у тому числі відстежує вільне місце на диску \
Поріг Medium (90%) - припинити приймати по SMTP пошту від зовнішніх відправників (пошта від MAPI клієнтів при цьому обробляється) \
Поріг High (99%) - обробка потоку пошти повністю припиняється.
Рішення: очистити, наприклад логи IIS (C: inetpub logs Log Files W3SVC1), збільшити розмір диска, відключити моніторинг Back Pressure (поганий варіант) або перенести транспортні чергу на інший диск достатнього об'єму.

Get-Service | ? name-like "MSExchangeTransport" | Stop-Service` зупинити служу черзі \
`Rename-Item "C:\Program Files\Microsoft\Exchange Server\V15\TransportRoles\data\Queue" "C:\Program Files\Microsoft\Exchange Server\V15\TransportRoles\data\Queue_old"` очистити базу черги \
`C:\Program Files\Microsoft\Exchange Server\V15\Bin\EdgeTransport.exe.config` конфігураційний файл, який містить шлях до бд з чергою (блок <appSettings> ключі <add key="QueueDatabasePath" value="$new_path " /> і QueueDatabaseLoggingPath) \
Для перенесення БД необхідно перемістити існуючі файли бази даних Mail.que і Trn.chk (контрольні точки для відстеження запису в логах) з вихідного розташування в нове. Перемістіть існуючі файли журналу транзакцій Trn.log, Trntmp.log, Trn nnnn.log , Trnres00001.jrs, Trnres00002.jrs та Temp.edb зі старого розташування до нового. tmp.edb - тимчасовий файл для перевірки схеми самої бази, перенесення не потрібно. \
Після запуску служби транспорту видалити стару базу даних черги та файли журналу транзакцій зі старого розташування.

### Defrag
`Get-MailboxDatabase-Status | ft Name, DatabaseSize, AvailableNewMailboxSpace` \
DatabaseSize - поточний розмір бази \
AvailableNewMailboxSpace - обсяг порожніх сторінок, простір, який можна звільнити при дефрагментації \
(DatabaseSize - AvailableNewMailboxSpace) x 1,1 - необхідно додатково мати вільного місця не менше 110% від поточного розміру бази (без урахування порожніх сторінок) \
`cd $path` \
`Dismount-Database "$path\$db_name"` відмонтувати БД \
`eseutil /d "$path\$db_name.edb"` \
`Mount-Database "$path\$db"` примонтувати БД

### DAG (Database Availability Group)
`Install-WindowsFeature -Name Failover-Clustering -ComputerName EXCH-MX-01` ґрунтується на технології Windows Server Failover Cluster \
`New-DatabaseAvailabilityGroup -Name dag-01 -WitnessServer fs-05 -WitnessDirectory C:\witness_exchange1` створити групу із зазначенням файлового свідка для кворуму \
Quorum - це процес голосування, в якому для ухвалення рішення потрібно мати більшість голосів, щоб зробити поточну копію бази даних активною. \
WitnessDirectory – використовується для зберігання даних файлового ресурсу-свідка. \
`Set-DatabaseAvailabilityGroup dag-01 –DatabaseAvailabilityGroupIPAdress $ip` змінити ip-адресу групи \
`Get-DatabaseAvailabilityGroup` список усіх груп \
`Get-DatabaseAvailabilityGroup -Identity dag-01` \
`Add-DatabaseAvailabilityGroupServer -Identity dag-01 -MailboxServer EXCH-MX-01` додати перший сервер (усі БД на серверах у DAG повинні зберігатися однаковим шляхом) \
`Add-MailboxDatabaseCopy -Identity db_name -MailboxServer EXCH-MX-04` додати копію БД \
`Get-MailboxDatabaseCopyStatus -Identity db_name\* | select Name,Status,LastInspectedLogTime` статус та час останнього копіювання журналу транзакій

Status: \
Mounted - робоча база \
Suspended - призупинено копіювання \
Healthy - робоча пасивна копія \
ServiceDown - недоступна (вимкнено сервер) \
Dismounted - відмонтована \
FailedAndSuspended - помилка та призупинення копіювання \
Resynchronizing - процес синхронізація, де поступово зменшуватиметься довжина черги \
CopyQueue Length – довжина реплікаційної черги копіювання (0 – значить усі зміни з активної бази репліковані у пасивну копію)

`Resume-MailboxDatabaseCopy -Identity db_name\EXCH-MX-04` відновити (Resume) або запустити копіювання бд на EXCH-MX-04 (зі статусу Suspended в Healthy) \
`Suspend-MailboxDatabaseCopy -Identity db_name\EXCH-MX-04` зупинити копіювання (в статус Suspended) \
`Update-MailboxDatabaseCopy -Identity db_name\EXCH-MX-04 -DeleteExistingFiles` оновити копію БД (зробити Full Backup) \
`Set-MailboxDatabaseCopy -Identity db_name\EXCH-MX-04 -ActivationPreference 1` змінити пріоритет для активації копій БД (яку використовувати, 1 – найвище значення) \
`Move-ActiveMailboxDatabase db_name -ActivateOnServer EXCH-MX-04 -MountDialOverride:None -Confirm:$false` включити копію БД в DAG (переключитися на активну копію) \
`Remove-MailboxDatabaseCopy -Identity db_name\EXCH-MX-04 -Confirm:$False` видалити копії пасивної бази в DAG-групі (у БД має бути відключено ведення циклічного журналу) \
`Remove-DatabaseAvailabilityGroupServer -Identity dag-01 -MailboxServer EXCH-MX-04 -ConfigurationOnly` видалити MX сервер із групи DAG \
`Import-Module FailoverClusters` \
`Get-ClusterNode EXCH-MX-04 | Remove-ClusterNode -Force` видалити вузол, що відмовив, з Windows Failover Cluster

`Get-DatabaseAvailabilityGroup | Get-DatabaseAvailabilityGroupHealth` моніторинг

### Index
`Get-MailboxDatabaseCopyStatus* | select name,status,ContentIndexState,ContentIndexErrorMessage,ActiveDatabaseCopy,LatestCopyBackupTime,CopyQueueLength` дізнатися стан роботи індксів БД та текст помилки, на якому сервері активна копія БД, дата останньої копії та поточна черга \
`Get-MailboxDatabaseCopyStatus -Identity $db_name\* | Format-List Name,ContentIndexState` відобразити список усіх копій конкретної БД на всіх серверах, та статус їх індексів, якщо у другого сервера статус Healthy, можна відновити з нього \
`Get-MailboxDatabaseCopyStatus -Identity $db_name\EXCH-MX-04 | Update-MailboxDatabaseCopy -SourceServer EXCH-MX-01 -CatalogOnly` відновити базу даних з копії \
`cd %PROGRAMFILES%\Microsoft\Exchange Server\V14\Scripts` або v15 для Exchange 2016 \
`.\ResetSearchIndex.ps1 $db_name` скрипт відновлення індексу

`Get-MailboxDatabaseCopyStatus* | where {$_.ContentIndexState -eq "Failed" -or $_.ContentIndexState -eq "FailedAndSuspended"}` відобразити в якій БД стався збій роботи (FailedAndSuspended) або індексу (ContentIndexState)

# TrueNAS

`import-Module TrueNas` \
`(Get-Module TrueNas).ExportedCommands` \
`Connect-TrueNasServer -Server tnas-01 -SkipCertificateCheck` \
`Get-TrueNasCertificate` налаштування сертифіката \
`Get-TrueNasSetting` налаштування мови, time zone, syslog level та server, https port \
`Get-TrueNasUser` список користувачів \
`Get-TrueNasSystemVersion` характеристики (Physical Memory, Model, Cores) та Uptime \
`Get-TrueNasSystemAlert` snmp для оповіщень \
`Get-TrueNasSystemNTP` список використовуваних NTP серверів \
`Get-TrueNasDisk` список розділів фізичного диска \
`Get-TrueNasInterface` мережеві інтерфейси \
`Get-TrueNasGlobalConfig` мережеві налаштування \
`Get-TrueNasDnsServer` налаштовані DNS-сервера \
`Get-TrueNasIscsiTarget` відобразити ID групи ініціаторів, які використовують таргет, використовуваний portal, authentification та authen-method \
`Get-TrueNasIscsiInitiator` відобразити групи ініціаторів \
`Get-TrueNasIscsiPortal` слухач (Listen) та порт \
`Get-TrueNasIscsiExtent` список ISCSi Target (статус роботи, шлях) \
`Get-TrueNasPool` список pool (Id, Path, Status, Healthy) \
`Get-TrueNasVolume -Type FILESYSTEM` список pool файлових систем \
`Get-TrueNasVolume -Type VOLUME` список розділів у pool та їх розмір \
`Get-TrueNasService | ft` список служб та їх статус \
`Start-TrueNasService ssh` запустити службу \
`Stop-TrueNasService ssh` зупинити службу

# Veeam

`Set-ExecutionPolicy AllSigned` or Set-ExecutionPolicy Bypass -Scope Process \
`Set-ExecutionPolicy Bypass-Scope Process-Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))` \
`choco install veeam-backup-and-replication-console` \
`Get-Module Veeam.Backup.PowerShell` \
`Get-Command -Module Veeam.Backup.PowerShell` or Get-VBRCommand \
`Connect-VBRServer -Server $srv -Credential $cred` or -User and -Password` - Port 9392` default \
`Get-VBRJob` \
`Get-VBRCommand *get*backup*` \
`Get-VBRComputerBackupJob` \
`Get-VBRBackup` \
`Get-VBRBackupRepository` \
`Get-VBRBackupSession` \
`Get-VBRBackupServerCertificate` \
`Get-VBRRestorePoint` \
`Get-VBRViProxy`

# REST API

`$url = "https://habr.com/ru/rss/users/Lifailon/publications/articles/?fl=ua"` RSS стрічка публікацій на Habr \
`Invoke-RestMethod $url` \
$iwr = Invoke-WebRequest -Uri $url \
$iwr | Get-Member`\
`$iwr.Content` \
`$iwr.StatusCode -eq 200` \
`$iwr.Headers` \
`$iwr.ParsedHtml | Select lastModified` \
`$iwr.Links | fl title,innerText,href` \
`$iwr.Images.src`

### Methods

**GET** - Read \
**POST** - Create \
**PATCH** - Partial update/modify \
**PUT** - Update/replace \
**DELETE** - Remove

### Download Image
```PowerShell
function Download-Image {
param (
[Parameter(Mandatory = $True)]$url
)
$folder = $url -replace "http.+://" -replace "/","-" -replace "-$"
$path = "$home\Pictures\$folder"
if (Test-Path $path) {
Remove-Item $path -Recurse -Force
New-Item -ItemType Directory $path > $null
} else {
New-Item -ItemType Directory $path > $null
}
$irm = Invoke-WebRequest -Uri $url
foreach ($img in $irm.Images.src) {
$name = $img -replace ".+/"
Start-Job {
Invoke-WebRequest $using:img -OutFile "$using:path\$using:name"
} > $null
}
while ($ True) {
$status_job = (Get-Job).State[-1]
if ($status_job -like "Completed"){
Get-Job | Remove-Job -Force
break
}}
$count_all = $irm.Images.src.Count
$count_down = (Get-Item $path\*).count
"Downloaded $count_down of $count_all files до $path"
}
````
`Download-Image -url https://losst.pro/`

### Token
```PowerShell
https://veeam-11:9419/swagger/ui/index.html
$Header = @{
"x-api-version" = "1.0-rev2"
}
$Body = @{
"grant_type" = "password"
"username" = "$login"
"password" = "$password"
}
$vpost = iwr "https://veeam-11:9419/api/oauth2/token" -Method POST -Headers $Header -Body $Body -SkipCertificateCheck
$vtoken = (($vpost.Content) -split '"')[3]
````
### GET
```PowerShell
$token = $vtoken | ConvertTo-SecureString -AsPlainText -Force
$vjob = iwr "https://veeam-11:9419/api/v1/jobs" -Method GET -Headers $Header -Authentication Bearer -Token

$Header = @{
"x-api-version" = "1.0-rev1"
"Authorization" = "Bearer $vtoken"
}
$vjob = iwr "https://veeam-11:9419/api/v1/jobs" -Method GET -Headers $Header -SkipCertificateCheck
$vjob = $vjob.Content | ConvertFrom-Json

$vjob = Invoke-RestMethod "https://veeam-11:9419/api/v1/jobs" -Method GET -Headers $Header -SkipCertificateCheck
$vjob.data.virtualMachines.includes.inventoryObject
````
# Pode
```PowerShell
Start-PodeServer {
Add-PodeEndpoint -Address localhost -Port "8080" -Protocol "HTTP"
### Get info endpoints
Add-PodeRoute -Path "/" -Method "GET" -ScriptBlock {
Write-PodeJsonResponse -Value @{
"service"="/api/service";
"process"="/api/process"
}
}
### GET
Add-PodeRoute -Path "/api/service" -Method "GET" -ScriptBlock {
Write-PodeJsonResponse -Value $(
Get-Service | Select-Object Name,@{
Name="Status"; Expression={[string]$_.Status}
}, @ {
Name="StartType"; Expression={[string]$_.StartType}
} | ConvertTo-Json
)
}
Add-PodeRoute -Path "/api/process" -Method "GET" -ScriptBlock {
Write-PodeJsonResponse -Value $(
Get-Process | Sort-Object -Descending CPU | Select-Object -First 15 ProcessName,
@{Name="ProcessorTime"; Expression={$_.TotalProcessorTime -replace "\.\d+$"}},
@{Name="Memory"; Expression={[string]([int]($_.WS / 1024kb))+"MB"}},
@{Label="RunTime"; Expression={((Get-Date) - $_.StartTime) -replace "\.\d+$"}}
)
}
Add-PodeRoute -Path "/api/process-html" -Method "GET" -ScriptBlock {
Write-PodeHtmlResponse -Value (
Get-Process | Sort-Object -Descending CPU | Select-Object -First 15 ProcessName,
@{Name="ProcessorTime"; Expression={$_.TotalProcessorTime -replace "\.\d+$"}},
@{Name="Memory"; Expression={[string]([int]($_.WS / 1024kb))+"MB"}},
@{Label="RunTime"; Expression={((Get-Date) - $_.StartTime) -replace "\.\d+$"}} # Auto ConvertTo-Html
)
}
### POST
Add-PodeRoute -Path "/api/service" -Method "POST" -ScriptBlock {
# https://pode.readthedocs.io/en/latest/Tutorials/WebEvent/
# $ WebEvent | Out-Default
$Value = $WebEvent.Data["ServiceName"]
$Status = (Get-Service -Name $Value).Status
Write-PodeJsonResponse -Value @{
"Name"="$Value";
"Status"="$Status";
}
}
}
````
`irm http://localhost:8080/api/service -Method Get` \
`irm http://localhost:8080/api/process -Method Get` \
`http://localhost:8080/api/process-html` використовувати браузер \
`irm http://localhost:8080/api/service -Method Post -Body @{"ServiceName" = "AnyDesk"}`

# Selenium

`Invoke-Expression(New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Lifailon/Deploy-Selenium/rsa/Deploy-Selenium-Drivers.ps1")` встановлення всіх драйверів і Chromium версії для драйвера
````
$path = "$home\Documents\Selenium\"
$log = "$path\ChromeDriver.log"
$ChromeDriver = "$path\ChromeDriver.exe"
$WebDriver = "$path\WebDriver.dll"
$SupportDriver = "$path\WebDriver.Support.dll"
$Chromium = (Get-ChildItem $path -Recurse | Where-Object Name -like chrome.exe).FullName
Add-Type -Path $WebDriver
Add-Type -Path $SupportDriver
try {
$ChromeOptions = New-Object OpenQA.Selenium.Chrome.ChromeOptions # створюємо об'єкт із налаштуваннями запуску браузера
$ChromeOptions.BinaryLocation = $Chromium # передаємо шлях до виконуваного файлу, який відповідає за запуск браузера
$ChromeOptions.AddArgument("start-maximized") # додаємо аргумент, який дозволяє запустити браузер на весь екран
#$ChromeOptions.AddArgument("start-minimized") # запускаємо браузер у вікні
#$ChromeOptions.AddArgument("window-size=400,800") # запускаємо браузер із заданими розмірами вікна в пікселях
$ChromeOptions.AcceptInsecureCertificates = $True # ігнорувати попередження на сайтах із не валідним сертифікатом
#$ChromeOptions.AddArgument("headless") # приховувати вікно браузера під час запуску
$ChromeDriverService = [OpenQA.Selenium.Chrome.ChromeDriverService]::CreateDefaultService($ChromeDriver) # створюємо об'єкт налаштувань служби драйвера
$ChromeDriverService.HideCommandPromptWindow = $True # відключаємо весь висновок логування драйвера в консоль (цей висновок не можна перенаправити)
$ChromeDriverService.LogPath = $log # вказати шлях до файлу з журналом
$ChromeDriverService.EnableAppendLog = $True # не перезаписувати журнал при кожному новому запуску
#$ChromeDriverService.EnableVerboseLogging = $True # крім INFO та помилок, записувати DEBUG повідомлення
$Selenium = New-Object OpenQA.Selenium.Chrome.ChromeDriver($ChromeDriverService, $ChromeOptions) # ініціалізуємо запуск із зазначеними налаштуваннями

$Selenium.Navigate().GoToUrl("https://google.com") # переходимо за вказаним посиланням у браузері
#$Selenium.Manage().Window.Minimize() # згорнути вікно браузера після запуску та переходу по потрібному url (що б вважати сторінку коректно)
# Шукаємо поле для введення тексту:
$Search = $Selenium.FindElements([OpenQA.Selenium.By]::Id('APjFqb'))
$Search = $Selenium.FindElements([OpenQA.Selenium.By]::XPath('//*[@id="APjFqb"]'))
$Search = $Selenium.FindElements([OpenQA.Selenium.By]::Name('q'))
$Search = $Selenium.FindElements([OpenQA.Selenium.By]::XPath('//*[@name="q"]'))
$Search = $Selenium.FindElements([OpenQA.Selenium.By]::ClassName('gLFyf'))
$Search = $Selenium.FindElements([OpenQA.Selenium.By]::CssSelector('[jsname="yZiJbe"]'))
$Search = $Selenium.FindElements([OpenQA.Selenium.By]::TagName('textarea')) | Where-Object ComputedAccessibleRole -eq combobox
$Search.SendKeys("calculator online") # передаємо текст вибраному елементу
$Search.SendKeys([OpenQA.Selenium.Keys]::Enter) # натискаємо Enter для виклику функції пошуку

Start-Sleep 1
$div = $Selenium.FindElements([OpenQA.Selenium.By]::TagName("div"))
$2 = $div | Where-Object {($_.ComputedAccessibleRole -eq "button") -and ($_.ComputedAccessibleLabel -eq "2")}
$2.Click()
$2.Click()
$plus = $div | Where-Object {($_.ComputedAccessibleRole -eq "button") -and ($_.Text -eq "+")}
$plus.Click()
$3 = $Selenium.FindElement([OpenQA.Selenium.By]::CssSelector('[jsname="KN1kY"]'))
$3.Click()
$3.Click()
$sum = $Selenium.FindElement([OpenQA.Selenium.By]::CssSelector('[jsname="Pt8tGc"]'))
$sum.Click()
$result = $Selenium.FindElement([OpenQA.Selenium.By]::CssSelector('[jsname="VssY5c"]')).Text
Write-Host "Результат: $result" -ForegroundColor Green
}
finally {
$Selenium.Close()
$Selenium.Quit()
}
````
### Selenium modules
```PowerShell
Invoke-RestMethod https://raw.githubusercontent.com/Lifailon/Selenium-Modules/rsa/Modules/Get-GPT/Get-GPT.psm1 | Out-File -FilePath "$(New-Item -Path "$($($Env:PSModulePath -split ";")[0])\Get-GPT" -ItemType Directory -Force)\Get-GPT.psm1" -Force
````
`Get-GPT "Виконуй роль калькулятора. Порахуй суму чисел: 22+33"`
```PowerShell
Invoke-RestMethod https://raw.githubusercontent.com/Lifailon/Selenium-Modules/rsa/Modules/Get-Translation/Get-Translation.psm1 | Out-File -FilePath "$(New-Item -Path "$($($Env:PSModulePath -split ";")[0])\Get-Translation" -ItemType Directory -Force)\Get-Translation.psm1" -Force
````
`Get-Translation -Provider DeepL -Text "I translating the text"` \
`Get-Translation -Provider DeepL -Text "Я перекладаю текст"` \
`Get-Translation -Provider Google -Text "I translating the text"` \
`Get-Translation -Provider Google -Text "Я перекладаю текст" -Language en`
```PowerShell
Invoke-RestMethod https://raw.githubusercontent.com/Lifailon/Selenium-Modules/rsa/Modules/Get-SpeedTest/Get-SpeedTest.psm1 | Out-File -FilePath "$(New-Item -Path "$($($Env:PSModulePath -split ";")[0])\Get-SpeedTest" -ItemType Directory -Force)\Get-SpeedTest.psm1" -Force
````
`Get-SpeedTest -Provider Libre` \
`Get-SpeedTest -Provider Open` \
`Get-SpeedTest-Provider Ookla`

# IE

`$ie.document.IHTMLDocument3_getElementsByTagName("input") | select name` отримати імена всіх Input Box \
`$ie.document.IHTMLDocument3_getElementsByTagName("button") | select innerText` отримати імена всіх Button \
`$ie.Document.documentElement.innerHTML` прочитати сирий Web Content (<input name="login" tabindex="100" class="input__control input__input" id="uniq32005644019429136"
`$All_Elements = $ie.document.IHTMLDocument3_getElementsByTagName("*")` забрати всі елементи \
$Go_Button = $All_Elements | ? innerText -like "go"` пошук елемента на ім'я \
`$Go_Button | select ie9_tagName` отримати TagName (SPAN) для швидкого подальшого пошуку \
`$SPAN_Elements = $ie.document.IHTMLDocument3_getElementsByTagName("SPAN")`
```PowerShell
$ie = New-Object -ComObject InternetExplorer.Application
$ie.navigate("https://yandex.ru")
$ie.visible = $true
$ie.document.IHTMLDocument3_getElementByID("login").value = "Login"
$ie.document.IHTMLDocument3_getElementByID("passwd").value = "Password"
$Button_Auth = ($ie.document.IHTMLDocument3_getElementsByTagName("button")) | ? innerText -match "Увійти"
$Button_Auth.Click()
$Result = $ie.Document.documentElement.innerHTML
$ie.Quit()
````
# COM

`$wshell = New-Object -ComObject Wscript.Shell` \
$wshell | Get-Member`\
`$link = $wshell.CreateShortcut("$Home\Desktop\Yandex.lnk")` створити ярлик \
`$link | Get-Member`\
`$link.TargetPath = "https://yandex.ru"` куди посилається (метод TargetPath об'єкта $link де зберігається об'єкт CreateShortcut) \
`$link.Save()` зберегти

`Set-WinUserLanguageList -LanguageList en-us,ru -Force` змінити мовну розкладку клавіатури

### Wscript.Shell.SendKeys

`(New-Object -ComObject Wscript.shell).SendKeys([char]173)` включити/вимкнути звук \
`$wshell.Exec("notepad.exe")` запустити програму \
`$wshell.AppActivate("Блокнот")` розгорнути запущену програму

`$wshell.SendKeys("Login")` текст \
`$wshell.SendKeys("{A 5}")` надрукувати літеру 5 разів поспіль \
`$wshell.SendKeys("%{TAB}")` ALT+TAB \
`$wshell.SendKeys("^")` CTRL \
`$wshell.SendKeys("%")` ALT \
`$wshell.SendKeys("+")` SHIFT \
`$wshell.SendKeys("{DOWN}")` вниз \
`$wshell.SendKeys("{UP}")` вгору \
`$wshell.SendKeys("{LEFT}")` вліво \
`$wshell.SendKeys("{RIGHT}")` праворуч \
`$wshell.SendKeys("{PGUP}")` PAGE UP \
`$wshell.SendKeys("{PGDN}")` PAGE DOWN \
`$wshell.SendKeys("{BACKSPACE}")` BACKSPACE/BKSP/BS \
`$wshell.SendKeys("{DEL}")` DEL/DELETE \
`$wshell.SendKeys("{INS}")` INS/INSERT \
`$wshell.SendKeys("{PRTSC}")` PRINT SCREEN \
`$wshell.SendKeys("{ENTER}")` \
`$wshell.SendKeys("{ESC}")` \
`$wshell.SendKeys("{TAB}")` \
`$wshell.SendKeys("{END}")` \
`$wshell.SendKeys("{HOME}")` \
`$wshell.SendKeys("{BREAK}")` \
`$wshell.SendKeys("{SCROLLLOCK}")` \
`$wshell.SendKeys("{CAPSLOCK}")` \
`$wshell.SendKeys("{NUMLOCK}")` \
`$wshell.SendKeys("{F1}")` \
`$wshell.SendKeys("{F12}")` \
`$wshell.SendKeys("{+}{^}{%}{~}{(}{)}{[}{]}{{}{}}")`
```PowerShell
function Get-AltTab {
(New-Object -ComObject wscript.shell).SendKeys("%{Tab}")
Start-Sleep $(Get-Random -Minimum 30 -Maximum 180)
Get-AltTab
}
Get-AltTab
````
### Wscript.Shell.Popup

`$wshell = New-Object -ComObject Wscript.Shell` \
`$output = $wshell.Popup("Виберіть дію?",0,"Заголовок",4)` \
`if ($output -eq 6) {"yes"} elseif ($output -eq 7) {"no"} else {"no good"}`
````
Type:
0 ОК
1 ОК та Скасувати
2 Стоп, Повтор, Пропустити
3 Так, Ні, Скасувати
4 Так і Ні
5 Повторення та скасування
16 Stop
32 Question
48 Exclamation
64 Information

Output:
-1 Timeout
1 ОК
2 Скасування
3 Стоп
4 Повторення
5 Пропустити
6 Так
7 Ні
````
### WScript.Network

`$wshell = New-Object -ComObject WScript.Network` \
$wshell | Get-Member`\
`$wshell.UserName` \
`$wshell.ComputerName` \
`$wshell.UserDomain`

### Shell.Application

`$wshell = New-Object -ComObject Shell.Application` \
$wshell | Get-Member`\
`$wshell.Explore("C:\")` \
`$wshell.Windows() | Get-Member` отримати доступ до відкритих у провіднику або браузері Internet Explorer вікон

`$shell = New-Object -Com Shell.Application` \
`$RecycleBin = $shell.Namespace(10)` \
`$RecycleBin.Items()`

### Outlook

`$Outlook = New-Object -ComObject Outlook.Application` \
`$Outlook | Get-Member`\
`$Outlook.Version`
```PowerShell
$Outlook = New-Object -ComObject Outlook.Application
$Namespace = $Outlook.GetNamespace("MAPI")
$Folder = $namespace.GetDefaultFolder(4)` вихідні
$Folder = $namespace.GetDefaultFolder(6)` вхідні
$Explorer = $Folder.GetExplorer()
$Explorer.Display()	
$Outlook.Quit()
````
### Microsoft.Update

`(New-Object -com 'Microsoft.Update.AutoUpdate').Settings` \
`(New-Object -com 'Microsoft.Update.AutoUpdate').Results` \
`(New-Timespan -Start ((New-Object -com 'Microsoft.Update.AutoUpdate').Results|Select -ExpandProperty LastInstallationSuccessDate) -End (Get-Date)).hours` кількість годин, що минули з останньої дати інсталяції оновлення безпеки у Windows.

# dotNET

`[System.Diagnostics.EventLog] | select Assembly,Module` \
`$EventLog = [System.Diagnostics.EventLog]::new("Application")` \
`$EventLog = New-Object -TypeName System.Diagnostics.EventLog -ArgumentList Application,192.168.3.100` \
`$EventLog | Get-Member -MemberType Method`\
`$EventLog.MaximumKilobytes` максимальний розмір журналу \
`$EventLog.Entries` переглянути журнал \
`$EventLog.Clear()` очистити журнал

`Join-Path C: Install Test` \
`[System.IO.Path]::Combine("C:", "Install", "Test")`

### Match

`[System.Math] | Get-Member -Static -MemberType Methods` \
`[System.Math]::Max(2,7)` \
`[System.Math]::Min(2,7)` \
`[System.Math]::Floor(3.9)` \
`[System.Math]::Truncate(3.9)`

### GeneratePassword

`Add-Type -AssemblyName System.Web` \
`[System.Web.Security.Membership]::GeneratePassword(10,2)`

### SoundPlayer
```PowerShell
$CriticalSound = New-Object System.Media.SoundPlayer
$CriticalSound.SoundLocation = "C:\WINDOWS\Media\Windows Critical Stop.wav"
$CriticalSound.Play()

$GoodSound = New-Object System.Media.SoundPlayer
$GoodSound.SoundLocation = "C:\WINDOWS\Media\tada.wav"
$GoodSound.Play()
````
### Static Class

`[System.Environment] | Get-Member -Static` \
`[System.Environment]::OSVersion` \
`[System.Environment]::Version` \
`[System.Environment]::MachineName` \
`[System.Environment]::UserName`

`[System.Diagnostics.Process] | Get-Member -Static` \
`[System.Diagnostics.Process]::Start('notepad.exe')`

### [Clicker]
```PowerShell
$cSource = @'
using System;
використовуючи System.Drawing;
використовуючи System.Runtime.InteropServices;
using System.Windows.Forms;
public class Clicker
{
//https://msdn.microsoft.com/en-us/library/windows/desktop/ms646270(v=vs.85).aspx
[StructLayout(LayoutKind.Sequential)]
struct INPUT
{
public int type; // 0 = INPUT_MOUSE,
// 1 = INPUT_KEYBOARD
// 2 = INPUT_HARDWARE
public MOUSEINPUT mi;
}
//https://msdn.microsoft.com/en-us/library/windows/desktop/ms646273(v=vs.85).aspx
[StructLayout(LayoutKind.Sequential)]
struct MOUSEINPUT
{
public int dx;
public int dy;
public int mouseData;
public int dwFlags;
public int time;
public IntPtr dwExtraInfo;
}
//Ці covers most use cases although complex mice may have additional buttons
//Те, що є додатковими constants ви можете використовувати для тих випадків, мовляв, msdn page
const int MOUSEEVENTF_MOVED = 0x0001;
const int MOUSEEVENTF_LEFTDOWN = 0x0002;
const int MOUSEEVENTF_LEFTUP = 0x0004;
const int MOUSEEVENTF_RIGHTDOWN = 0x0008;
const int MOUSEEVENTF_RIGHTUP = 0x0010;
const int MOUSEEVENTF_MIDDLEDOWN = 0x0020;
const int MOUSEEVENTF_MIDDLEUP = 0x0040;
const int MOUSEEVENTF_WHEEL = 0x0080;
const int MOUSEEVENTF_XDOWN = 0x0100;
const int MOUSEEVENTF_XUP = 0x0200;
const int MOUSEEVENTF_ABSOLUTE = 0x8000;
const int screen_length = 0x10000;
//https://msdn.microsoft.com/en-us/library/windows/desktop/ms646310(v=vs.85).aspx
[System.Runtime.InteropServices.DllImport("user32.dll")]
extern static uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);
public static void LeftClickAtPoint(int x, int y)
{
//Move the mouse
INPUT[] input = new INPUT[3];
input[0].mi.dx = x*(65535/System.Windows.Forms.Screen.PrimaryScreen.Bounds.Width);
input[0].mi.dy = y*(65535/System.Windows.Forms.Screen.PrimaryScreen.Bounds.Height);
input[0].mi.dwFlags = MOUSEEVENTF_MOVED | MOUSEEVENTF_ABSOLUTE;
//Left mouse button down
input[1].mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
//Left mouse button up
input[2].mi.dwFlags = MOUSEEVENTF_LEFTUP;
SendInput(3, input, Marshal.SizeOf(input[0]));
}
}
'@
````
`Add-Type -TypeDefinition $cSource -ReferencedAssemblies System.Windows.Forms,System.Drawing` \
`[Clicker]::LeftClickAtPoint(1900,1070)`

### [Audio]
```PowerShell
Add-Type -Language CsharpVersion3 -TypeDefinition @"
використовуючи System.Runtime.InteropServices;
[Guid("5CDF2C82-841E-4546-9722-0CF74078229A"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IAudioEndpointVolume {
// f(), g(), ... є unused COM метод slots. Define these if you care
int f(); int g(); int h(); int i();
int SetMasterVolumeLevelScalar(float fLevel, System.Guid pguidEventContext);
int j();
int GetMasterVolumeLevelScalar(out float pfLevel);
int k(); int l(); int m(); int n();
int SetMute([MarshalAs(UnmanagedType.Bool)] bool bMute, System.Guid pguidEventContext);
int GetMute (out bool pbMute);
}
[Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IMMDevice {
int Activate(ref System.Guid id, int clsCtx, int activationParams, від IAudioEndpointVolume aev);
}
[Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IMMDeviceEnumerator {
int f(); // Unused
int GetDefaultAudioEndpoint(int dataFlow, int role, out IMMDevice endpoint);
}
[ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")] class MMDeviceEnumeratorComObject { }
public class Audio {
static IAudioEndpointVolume Vol() {
var enumerator = новий MMDeviceEnumeratorComObject() as IMMDeviceEnumerator;
IMMDevice dev = null;
Marshal.ThrowExceptionForHR(enumerator.GetDefaultAudioEndpoint(/*eRender*/ 0, /*eMultimedia*/ 1, out dev));
IAudioEndpointVolume epv = null;
var epvid = typeof(IAudioEndpointVolume).GUID;
Marshal.ThrowExceptionForHR(dev.Activate(ref epvid, /*CLSCTX_ALL*/ 23, 0, out epv));
return epv;
}
public static float Volume {
get {float v = -1; Marshal.ThrowExceptionForHR(Vol().GetMasterVolumeLevelScalar(out v)); return v;}
set {Marshal.ThrowExceptionForHR(Vol().SetMasterVolumeLevelScalar(value, System.Guid.Empty));}
}
public static bool Mute {
get {bool mute; Marshal.ThrowExceptionForHR(Vol().GetMute(out mute)); return mute; }
set { Marshal.ThrowExceptionForHR(Vol().SetMute(value, System.Guid.Empty)); }
}
}
"@
````
`[Audio]::Volume = 0.50` \
`[Audio]::Mute = $true`

### NetSessionEnum

Function: https://learn.microsoft.com/ru-ua/windows/win32/api/lmshare/nf-lmshare-netsessionenum?redirectedfrom=MSDN \
Source: https://fuzzysecurity.com/tutorials/24.html
```PowerShell
function Invoke-NetSessionEnum {
param (
[Parameter(Mandatory = $True)][string]$HostName
)
Add-Type -TypeDefinition @"
using System;
використовуючи System.Diagnostics;
використовуючи System.Runtime.InteropServices;
[StructLayout(LayoutKind.Sequential)]
public struct SESSION_INFO_10
{
[MarshalAs(UnmanagedType.LPWStr)]public string OriginatingHost;
[MarshalAs(UnmanagedType.LPWStr)]public string DomainUser;
public uint SessionTime;
public uint IdleTime;
}
public static class Netapi32
{
[DllImport("Netapi32.dll", SetLastError=true)]
public static extern int NetSessionEnum(
[In,MarshalAs(UnmanagedType.LPWStr)] string ServerName,
[In,MarshalAs(UnmanagedType.LPWStr)] string UncClientName,
[In,MarshalAs(UnmanagedType.LPWStr)] string UserName,
Int32 Level,
out IntPtr bufptr,
int prefmaxlen,
ref Int32 entriesread,
ref Int32 totalentries,
ref Int32 resume_handle);
         
[DllImport("Netapi32.dll", SetLastError=true)]
public static extern int NetApiBufferFree(
IntPtr Buffer);
}
"@
# Create SessionInfo10 Struct
$SessionInfo10 = New-Object SESSION_INFO_10
$SessionInfo10StructSize = [System.Runtime.InteropServices.Marshal]::SizeOf($SessionInfo10)` Grab size to loop bufptr
$SessionInfo10 = $SessionInfo10.GetType()` Hacky, but we need this ;))
# NetSessionEnum params
$OutBuffPtr = [IntPtr]::Zero` Struct output buffer
$EntriesRead = $TotalEntries = $ResumeHandle = 0` Counters & ResumeHandle
$CallResult = [Netapi32]::NetSessionEnum($HostName, "", "", 10, [ref]$OutBuffPtr, -1, [ref]$EntriesRead, [ref]$TotalEntries, [ref]$ResumeHandle)
if ($CallResult -ne 0){
echo "Mmm something went wrong!`nError Code: $CallResult"
}
else {
if ([System.IntPtr]::Size -eq 4) {
echo "`nNetapi32::NetSessionEnum Buffer Offset --> 0x$("{0:X8}" -f $OutBuffPtr.ToInt32())"
}
else {
echo "`nNetapi32::NetSessionEnum Buffer Offset --> 0x$("{0:X16}" -f $OutBuffPtr.ToInt64())"
}
echo "Result-set contains $EntriesRead session(s)!"
# Change buffer offset to int
$BufferOffset = $OutBuffPtr.ToInt64()
# Loop buffer entries and cast pointers as SessionInfo10
for ($Count = 0; ($Count -lt $EntriesRead); $Count++){
$NewIntPtr = New-Object System.Intptr -ArgumentList $BufferOffset
$Info = [system.runtime.interopservices.marshal]::PtrToStructure($NewIntPtr,[type]$SessionInfo10)
$Info
$BufferOffset = $BufferOffset + $SessionInfo10StructSize
}
echo "`nCalling NetApiBufferFree, no memleaks here!"
[Netapi32]::NetApiBufferFree($OutBuffPtr) |Out-Null
}
}
````
`Invoke-NetSessionEnum localhost`

### CopyFile

Function: https://learn.microsoft.com/ru-ua/windows/win32/api/winbase/nf-winbase-copyfile \
Source: https://devblogs.microsoft.com/scripting/use-powershell-to-interact-with-the-windows-api-part-1/
```PowerShell
$MethodDefinition = @"
[DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
public static extern bool CopyFile(string lpExistingFileName, string lpNewFileName, bool bFailIfExists);
"@
$Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name "Kernel32" -Namespace "Win32" -PassThru
$Kernel32::CopyFile("$($Env:SystemRoot)\System32\calc.exe", "$($Env:USERPROFILE)\Desktop\calc.exe", $False)
````
### ShowWindowAsync

Function: https://learn.microsoft.com/ru-ru/windows/win32/api/winuser/nf-winuser-showwindowasync
```PowerShell
$Signature = @"
[DllImport("user32.dll")]public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
"@
$ShowWindowAsync = Add-Type -MemberDefinition $Signature -Name "Win32ShowWindowAsync" -Namespace Win32Functions -PassThru
$ShowWindowAsync | Get-Member -Static
$ShowWindowAsync::ShowWindowAsync((Get-Process -Id $pid).MainWindowHandle, 2)
$ShowWindowAsync::ShowWindowAsync((Get-Process -Id $Pid).MainWindowHandle, 3)
$ShowWindowAsync::ShowWindowAsync((Get-Process -Id $Pid).MainWindowHandle, 4)
````
### GetAsyncKeyState

Function: https://learn.microsoft.com/ru-ua/windows/win32/api/winuser/nf-winuser-getasynckeystate

`Add-Type -AssemblyName System.Windows.Forms` \
`[int][System.Windows.Forms.Keys]::F1` визначити номер [Int] клавіші за її назвою \
`65..90 | % {"{0} = {1}" -f $_, [System.Windows.Forms.Keys]$_}` порядковий номер букв (A..Z)
```PowerShell
function Get-ControlKey {
$key = 112
$Signature = @'
[DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)]
public static extern short GetAsyncKeyState(int virtualKeyCode);
'@
Add-Type -MemberDefinition $Signature -Name Keyboard -Namespace PsOneApi
[bool]([PsOneApi.Keyboard]::GetAsyncKeyState($key) -eq -32767)
}

Write-Warning 'Press F1 to exit'
while ($ true) {
Write-Host '.' -NoNewline
if (Get-ControlKey) {
break
}
Start-Sleep -Seconds 0.5
}
````
# Console API

Source: https://powershell.one/tricks/input-devices/detect-key-press

`[Console] | Get-Member -Static` \
`[Console]::BackgroundColor = "Blue"` \
`[Console]::OutputEncoding` кодування, що використовується в поточній сесії \
`[Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding("utf-8")` змінити кодування для відображення кирилиці \
`[Console]::outputEncoding = [System.Text.Encoding]::GetEncoding("cp866")` для ISE \
`[Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding("windows-1251")` для ps2exe \
Get-Service | Out-File $home\Desktop\Service.txt -Encoding oem` > \
Get-Service | Out-File $home\Desktop\Service.txt -Append` >>
```PowerShell
do {
if ([Console]::KeyAvailable) {
$keyInfo = [Console]::ReadKey($true)
break
}
Write-Host "." -NoNewline
sleep 1
} while ($true)
Write-Host
$keyInfo

function Get-KeyPress {
param (
[Parameter(Mandatory)][ConsoleKey]$Key,
[System.ConsoleModifiers]$ModifierKey = 0
)
if ([Console]::KeyAvailable) {
$pressedKey = [Console]::ReadKey($true)
$isPressedKey = $key -eq $pressedKey.Key
if ($isPressedKey) {
$pressedKey.Modifiers -eq $ModifierKey
} else {
[Console]::Beep(1800, 200)
$false
}}}

Write-Warning 'Press Ctrl+Shift+Q to exit'
do {
Write-Host "." -NoNewline
$pressed = Get-KeyPress -Key Q -ModifierKey 'Control,Shift'
if ($pressed) {break}
sleep 1
} while ($true)
````
# Drawing

API: https://learn.microsoft.com/en-us/dotnet/api/system.drawing?view=net-7.0&redirectedfrom=MSDN
```PowerShell
Add-Type -AssemblyName System.Drawing
$Width = 800
$Height = 400
$image = New-Object System.Drawing.Bitmap($Width,$Height)
$graphic = [System.Drawing.Graphics]::FromImage($image)
$background_color = [System.Drawing.Brushes]::Blue # встановити колір фону (синій)
$graphic.FillRectangle($background_color, 0, 0, $image.Width, $image.Height)
$text_color = [System.Drawing.Brushes]::White # задати колір тексту (білий)
$font = New-Object System.Drawing.Font("Arial", 20, [System.Drawing.FontStyle]::Bold) # встановити шрифт
$text = "PowerShell" # вказати текст
$text_position = New-Object System.Drawing.RectangleF(320, 180, 300, 100) # задати положення тексту (x, y, width, height)
$graphic.DrawString($text, $font, $text_color, $text_position) # нанести текст на зображення
$image.Save("$home\desktop\powershell_image.bmp", [System.Drawing.Imaging.ImageFormat]::Bmp) # зберегти зображення
$image.Dispose() # звільнення ресурсів
````
`$path = "$home\desktop\powershell_image.bmp"` \
`Invoke-Item $path`
```PowerShell
$src_image = [System.Drawing.Image]::FromFile($path)
$Width = 400
$Height = 200
$dst_image = New-Object System.Drawing.Bitmap -ArgumentList $src_image, $Width, $Height # змінити розмір зображення
$dst_image.Save("$home\desktop\powershell_image_resize.bmp", [System.Drawing.Imaging.ImageFormat]::Bmp)

$rotated_image = $src_image.Clone() # створити копію вихідного зображення
$rotated_image.RotateFlip([System.Drawing.RotateFlipType]::Rotate180FlipNone) # перевернути зображення на 180 градусів
$rotated_image.Save("$home\desktop\powershell_image_rotated.bmp", [System.Drawing.Imaging.ImageFormat]::Bmp)
$src_image.Dispose() # закрити (відпустити) вихідний файл
````
# ObjectEvent
```PowerShell
$Timer = New-Object System.Timers.Timer
$Timer.Interval = 1000
Register-ObjectEvent -InputObject $Timer -EventName Elapsed -SourceIdentifier Timer.Output -Action {
$Random = Get-Random -Min 0 -Max 100
Write-Host $Random
}
$Timer.Enabled = $True
````
`$Timer.Enabled = $False` зупинити \
$Timer | Get-Member -MemberType Event` відобразити список всіх подій об'єкта \
`Get-EventSubscriber` список зареєстрованих підписок на події у поточній сесії \
`Unregister-Event -SourceIdentifier Timer.Output` видаляє реєстрацію підписки на подію на ім'я події (EventName) або всі * \
`-Forward` перенаправляє події з віддаленого сеансу (New-PSSession) у локальний сеанс \
`-SupportEvent` не виводить результат реєстрації події на екран (і Get-EventSubscriber та Get-Job)
````
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
$date = Get-Date -f hh:mm:ss
(New-Object -ComObject Wscript.Shell).Popup("PowerShell Exit: $date",0,"Action",64)
}
````
# Sockets

### UDP Socket
Source: https://cloudbrothers.info/en/test-udp-connection-powershell/
```PowerShell
function Start-UDPServer {
param(
$Port = 5201
)
$RemoteComputer = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
do {
$UdpObject = New-Object System.Net.Sockets.UdpClient($Port)
$ReceiveBytes = $UdpObject.Receive([ref]$RemoteComputer)
$UdpObject.Close()
$ASCIIEncoding = New-Object System.Text.ASCIIEncoding
[string]$ReturnString = $ASCIIEncoding.GetString($ReceiveBytes)
[PSCustomObject]@{
LocalDateTime = $(Get-Date -UFormat "%Y-%m-%d %T")
ClientIP = $RemoteComputer.address.ToString()
ClientPort = $RemoteComputer.Port.ToString()
Message = $ReturnString
}
} while (1)
}
````
`Start-UDPServer -Port 5201`

### Test-NetUDPConnection
```PowerShell
function Test-NetUDPConnection {
param(
[string]$ComputerName = "127.0.0.1",
[int32]$PortServer = 5201,
[int32]$PortClient = 5211,
$Message
)
begin {
$UdpObject = New-Object system.Net.Sockets.Udpclient($PortClient)
$UdpObject.Connect($ComputerName, $PortServer)
}
process {
$ASCIIEncoding = New-Object System.Text.ASCIIEncoding
if (!$Message) {$Message = Get-Date -UFormat "%Y-%m-%d %T"}
$Bytes = $ASCIIEncoding.GetBytes($Message)
[void]$UdpObject.Send($Bytes, $Bytes.length)
}
end {
$UdpObject.Close()
}
}
````
`Test-NetUDPConnection -ComputerName 127.0.0.1 -PortServer 5201` \
`Test-NetUDPConnection -ComputerName 127.0.0.1 -PortServer 514 -Message "<30>May 31 00:00:00 HostName multipathd[784]: Test message"`

### TCP Socket
```PowerShell
function Start-TCPServer {
param(
$Port = 5201
)
do {
$TcpObject = New-Object System.Net.Sockets.TcpListener($port)
$ReceiveBytes = $TcpObject.Start()
$ReceiveBytes = $TcpObject.AcceptTcpClient()
$TcpObject.Stop()
$ReceiveBytes.Client.RemoteEndPoint | select Address,Port
} while (1)
}
````
`Start-TCPServer -Port 5201` \
`Test-NetConnection -ComputerName 127.0.0.1 -Port 5201`

### WakeOnLan
Broadcast package consisting of 6 byte filled "0xFF" and then 96 byte where the mac address is repeated 16 times
```PowerShell
function Send-WOL {
param (
[Parameter(Mandatory = $True)]$Mac,
$IP,
[int]$Port = 9
)
$Mac = $Mac.replace(":", "-")
if (!$IP) {$IP = [System.Net.IPAddress]::Broadcast}
$SynchronizationChain = [byte[]](,0xFF * 6)
$ByteMac = $Mac.Split("-") | %{[byte]("0x" + $_)}
$Package = $SynchronizationChain + ($ByteMac * 16)
$UdpClient = New-Object System.Net.Sockets.UdpClient
$UdpClient.Connect($IP, $port)
$UdpClient.Send($Package, $Package.Length)
$UdpClient.Close()
}
````
`Send-WOL-Mac "D8-BB-C1-70-A3-4E"`\
`Send-WOL -Mac "D8-BB-C1-70-A3-4E" -IP 192.168.3.100`

### Encoding
`$ByteText = [System.Text.Encoding]::UTF8.GetBytes("password")` \
`$Text = [System.Text.Encoding]::UTF8.GetString($ByteText)`

### Base64
`$text = "password"` \
`$byte = [System.Text.Encoding]::Unicode.GetBytes($text)` \
`$base64 = [System.Convert]::ToBase64String($byte)` \
`$decode_base64 = [System.Convert]::FromBase64String($base64)` \
`$decode_string = [System.Text.Encoding]::Unicode.GetString($decode_base64)`

`$path_image = "$home\Documents\1200x800.jpg"` \
`$BBase64 = [System.Convert]::ToBase64String((Get-Content $path_image -Encoding Byte))` \
`Add-Type -assembly System.Drawing` \
`$Image = [System.Drawing.Bitmap]::FromStream([IO.MemoryStream][Convert]::FromBase64String($BBase64))` \
`$Image.Save("$home\Desktop\1200x800.jpg")`

### HTTP Listener
```PowerShell
$httpListener = New-Object System.Net.HttpListener
$httpListener.Prefixes.Add("http://+:8888/")
$httpListener.Start()
while (!([console]::KeyAvailable)) {
$ info = Get-Service | select name,status | ConvertTo-HTML
$context = $httpListener.GetContext()
$context.Response.StatusCode = 200
$context.Response.ContentType = 'text/HTML'
$WebContent = $info
$EncodingWebContent = [Text.Encoding]::UTF8.GetBytes($WebContent)
$context.Response.OutputStream.Write($EncodingWebContent , 0, $EncodingWebContent.Length)
$context.Response.Close()
Get-NetTcpConnection -LocalPort 8888
(Get-Date).
}
$httpListener.Close()
````
### WebClient
`[System.Net.WebClient] | Get-Member`\
`(New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Lifailon/PowerShell-Commands/rsa/README.md")`

### Certificate
```PowerShell
function Get-WebCertificate ($srv) {
$iwr = iwr $srv
$status_code = $iwr.StatusCode
$status = $iwr.BaseResponse.StatusCode
$info = $iwr.BaseResponse.Server
$spm = [System.Net.ServicePointManager]::FindServicePoint($srv)
$date_end = $spm.Certificate.GetExpirationDateString()
$cert_name = ($spm.Certificate.Subject) -replace "CN="
$cert_owner = ((($spm.Certificate.Issuer) -split ", ") | where {$_ -match "O="}) -replace "O="
$Collections = New-Object System.Collections.Generic.List[System.Object]
$Collections.Add([PSCustomObject]@{
Host = $ srv;
Server = $ info;
Status = $ status;
StatusCode = $status_code;
Certificate = $cert_name;
Issued = $cert_owner;
End = $date_end
})
$Collections
}
````
`Get-WebCertificate https://google.com`

# Excel
```PowerShell
$path = "$home\Desktop\Services-to-Excel.xlsx"
$Excel = New-Object -ComObject Excel.Application
$Excel.Visible = $false` відключити відкриття GUI
$ExcelWorkBook = $Excel.Workbooks.Add()` Створити книгу
$ExcelWorkSheet = $ExcelWorkBook.Worksheets.Item(1)` Створити лист
$ExcelWorkSheet.Name = "Services"` задати ім'я аркуша
$ExcelWorkSheet.Cells.Item(1,1) = "Name service"
# Задати імена стовпців:
$ExcelWorkSheet.Cells.Item(1,2) = "Description"
$ExcelWorkSheet.Cells.Item(1,3) = "Status"
$ExcelWorkSheet.Cells.Item(1,4) = "Startup type"
$ExcelWorkSheet.Rows.Item(1).Font.Bold = $true` виділити жирним шрифтом
$ExcelWorkSheet.Rows.Item(1).Font.size=14
# Задати ширину колонок:
$ExcelWorkSheet.Columns.Item(1).ColumnWidth=30
$ExcelWorkSheet.Columns.Item(2).ColumnWidth=80
$ExcelWorkSheet.Columns.Item(3).ColumnWidth=15
$ExcelWorkSheet.Columns.Item(4).ColumnWidth=25
$services = Get-Service
$counter = 2` встановити початковий номер рядка для запису
foreach ($service in $services) {
$status = $service.Status
if ($status -eq 1) {
$status_type = "Stopped"
} elseif ($status -eq 4) {
$status_type = "Running"
}
$Start = $service.StartType
if ($Start -eq 1) {
$start_type = "Delayed start"
} elseif ($Start -eq 2) {
$start_type = "Automatic"
} elseif ($Start -eq 3) {
$start_type = "Manually"
} elseif ($Start -eq 4) {
$start_type = "Disabled"
}
$ExcelWorkSheet.Columns.Item(1).Rows.Item($counter) = $service.Name
$ExcelWorkSheet.Columns.Item(2).Rows.Item($counter) = $service.DisplayName
$ExcelWorkSheet.Columns.Item(3).Rows.Item($counter) = $status_type
$ExcelWorkSheet.Columns.Item(4).Rows.Item($counter) = $start_type
if ($status_type -eq "Running") {
$ExcelWorkSheet.Columns.Item(3).Rows.Item($counter).Font.Bold = $true
}
$counter++` +1 збільшити для лічильника рядка Rows
}
$ExcelWorkBook.SaveAs($path)
$ExcelWorkBook.close($true)
$Excel.Quit()
````
### Excel.Application.Open
```PowerShell
$path = "$home\Desktop\Services-to-Excel.xlsx"
$Excel = New-Object -ComObject Excel.Application
$Excel.Visible = $false
$ExcelWorkBook = $excel.Workbooks.Open($path)` відкрити xlsx-файл
$ExcelWorkBook.Sheets | select Name,Index` відобразити аркуші
$ExcelWorkSheet = $ExcelWorkBook.Sheets.Item(1)` відкрити аркуш за номером Index
1..100 | %{$ExcelWorkSheet.Range("A$_").Text}` прочитати значення зі стовпця А рядка з 1 по 100
$Excel.Quit()
````
### ImportExcel
`Install-Module -Name ImportExcel` \
`$data | Export-Excel .\Data.xlsx` \
`$data = Import-Excel .\Data.xlsx`

$data = ps \
`$Chart = New-ExcelChartDefinition -XRange CPU -YRange WS -Title "Process" -NoLegend` \
`$data | Export-Excel .\ps.xlsx -AutoNameRange -ExcelChartDefinition $Chart -Show`

# CSV

Get-Service | Select Name,DisplayName,Status,StartType | Export-Csv -path "$home\Desktop\Get-Service.csv" -Append -Encoding Default` експортувати до csv (-Encoding UTF8) \
`Import-Csv "$home\Desktop\Get-Service.csv" -Delimiter ","` імпортувати масив
```PowerShell
$data = ConvertFrom-Csv@"
Region,State,Units,Price
West,Texas,927,923.71
$null,Tennessee,466,770.67
"@
````
`$systeminfo = systeminfo /FO csv | ConvertFrom-Csv` висновок роботи програми в CSV та конвертація в об'єкт \
`$systeminfo."Повний обсяг фізичної пам'яті"` \
`$systeminfo."Доступна фізична пам'ять"`

### ConvertFrom-String
```PowerShell
'
log =
{
level = 4;
};
'| ConvertFrom-String` створює PSCustomObject (розбиває по пробілах, видаляє всі прогалини та порожні рядки)
````
### ConvertFrom-StringData
```PowerShell
"
key1 = value1
key2 = value2
" | ConvertFrom-StringData # створює Hashtable
````
# XML
```PowerShell
$xml = [xml](Get-Content $home\desktop\test.rdg)` прочитати вміст XML-файлу
$xml.load("$home\desktop\test.rdg")` відкрити файл
$xml.RDCMan.file.group.properties.name` імена груп
$xml.RDCMan.file.group.server.properties` імена всіх серверів
$xml.RDCMan.file.group[3].server.properties` список серверів у 4-й групі
($xml.RDCMan.file.group[3].server.properties | ? name -like ADIRK).Name = "New-Name"` змінити значення
$xml.RDCMan.file.group[3].server[0].properties.displayName = "New-displayName"
$xml.RDCMan.file.group[3].server[1].RemoveAll()` видалити об'єкт (2-й сервер у списку)
$xml.Save($file)` зберегти вміст об'єкта у файлі
````
Get-Service | Export-Clixml -path $home\desktop\test.xml` експортувати об'єкт PowerShell у XML \
`Import-Clixml -Path $home\desktop\test.xml` імпортувати об'єкт XML у PowerShell \
`ConvertTo-Xml (Get-Service)`

### Get-CredToXML
```PowerShell
function Get-CredToXML {
param (
$CredFile = "$home\Documents\cred.xml"
)
if (Test-Path $CredFile) {
Import-Clixml -path $CredFile
}
elseif (!(Test-Path $CredFile)) {
$Cred = Get-Credential -Message "Enter credential"
if ($Cred -ne $null) {
$Cred | Export-CliXml -Path $CredFile
$Cred
}
else {
return
}
}
}
````
`$Cred = Get-CredToXML` \
`$Login = $Cred.UserName` \
`$PasswordText = $Cred.GetNetworkCredential().password` отримати пароль у текстовому вигляді

### XmlWriter (Extensible Markup Language)
```PowerShell
$XmlWriterSettings = New-Object System.Xml.XmlWriterSettings
$XmlWriterSettings.Indent = $true` увімкнути відступи
$XmlWriterSettings.IndentChars = " "` задати відступ

$XmlFilePath = "$home\desktop\test.xml"
$XmlObjectWriter = [System.XML.XmlWriter]::Create($XmlFilePath, $XmlWriterSettings)` створити документ
$XmlObjectWriter.WriteStartDocument()` розпочати запис у документ

$XmlObjectWriter.WriteComment("Comment")
$XmlObjectWriter.WriteStartElement("Root")` створити стартовий елемент, який містить дочірні об'єкти
$XmlObjectWriter.WriteStartElement("Configuration")` створити перший дочірній елемент для BaseSettings
$XmlObjectWriter.WriteElementString("Language","RU")
$XmlObjectWriter.WriteStartElement("Fonts") 		# <Fonts>
$XmlObjectWriter.WriteElementString("Name","Arial")
$XmlObjectWriter.WriteElementString("Size","12")
$XmlObjectWriter.WriteEndElement() 	# </Fonts>
$XmlObjectWriter.WriteEndElement()` кінцевий елемент </Configuration>
$XmlObjectWriter.WriteEndElement()` кінцевий елемент </Root>

$XmlObjectWriter.WriteEndDocument()` завершити запис до документа
$XmlObjectWriter.Flush()
$XmlObjectWriter.Close()
````
### CreateElement
```PowerShell
$xml = [xml](gc $home\desktop\test.xml)
$xml.Root.Configuration.Fonts
$NewElement = $xml.CreateElement("Fonts")` вибрати елемент, куди додати
$NewElement.set_InnerXML("<Name>Times New Roman</Name><Size>14</Size>")` Заповнити значеннями дочірні елементи Fonts
$xml.Root.Configuration.AppendChild($NewElement)` додати елемент новим рядком у Configuration (батько Fonts)
$xml.Save("$home\desktop\test.xml")
````
#JSON
```PowerShell
$log = '
{
"log": {
"level": 7
}
}
'| ConvertFrom-Json

Get-Service | ConvertTo-Json

$OOKLA = '
{
"result" :
{"date":1683534970,"id":"14708271987","connection_icon":"wireless","download":33418,"upload":35442,"latency":15,"distance":50,"country_code" :"RU","server_id":2707,"server_name":"Bryansk","sponsor_name":"DOM.RU","sponsor_url":null,"connection_mode":"multi","isp_name":"Resource Link ","isp_rating":"4.0","test_rank":63,"test_grade":"B-","test_rating":4,"idle_latency":"17","download_latency":"116","upload_latency" :"75","additional_servers":
[{"server_id":8191,"server_name":"Bryansk","sponsor_name":"SectorTelecom.ru"},{"server_id":46278,"server_name":"Fokino","sponsor_name":"Fokks - Promyshlennaya avtomatika Ltd."},{"server_id":18218,"server_name":"Bryansk","sponsor_name":"RIA-link Ltd."}],
"path":"result\u002F14708271987","hasSecondary":true
}
}
'| ConvertFrom-Json
$ookla.result
````
#YAML
```PowerShell
Import-Module PSYaml` використовується в Docker/Ansible
$netplan = "
network:` словник на кшталт - ключ : значення з вкладеними словниками
ethernets:
ens160:
dhcp4: yes
dhcp6: no
nameservers:
addresses:` [8.8.8.8, 1.1.1.1]` список даних (рядків)
		- 8.8.8.8
		- 1.1.1.1
version: 2
"
$network = ConvertFrom-Yaml $netplan
$network.Values.ethernets.ens160.nameservers

$DataType = "
int: !!int 10.1
flo: !!float 10.1
str: !!str string
bool: !!bool` boolean
"
````
#HTML

### ConvertFrom-Html
```PowerShell
function ConvertFrom-Html {
param (
[Parameter(ValueFromPipeline)]$url
)
$irm = Invoke-RestMethod $url
$HTMLFile = New-Object -ComObject HTMLFile
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($irm)
$HTMLFile.write($Bytes)
($HTMLFile.all | where {$_.tagname -eq "body"}).innerText
}

$apache_status = "http://192.168.3.102/server-status"
$apache_status | ConvertFrom-HTML
````
### ConvertTo-Html

Get-Process | select Name, CPU | ConvertTo-Html -As Table > "$home\desktop\proc-table.html"` висновок у форматі List (Format-List) або Table (Format-Table)
```PowerShell
$servers = "ya.ru","ya.com","google.com"
$path = "$home\Desktop\Ping.html"
$header = @"
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head>
<title>Звіт про статус серверів</title>
<style type="text/css">
<!--
body {
background-color: #E0E0E0;
font-family: sans-serif
}
table, th, td {
background-color: white;
border-collapse:collapse;
border: 1px solid black;
padding: 5px
}
-->
</style>
"@
$body = @"
<h1>Ping status</h1>
<p>$(get-date -Format "dd.MM.yyyy hh:mm").</p>
"@
$results = foreach ($server in $servers) {
if (Test-Connection $server -Count 1 -ea 0 -Quiet) {
$status = "Up"
}
else {
$status = "Down"
}
[PSCustomObject]@{
Name = $server
Status = $status
}
}
$results | ConvertTo-Html -head $header -body $body | foreach {
$_ -replace "<td>Down</td>","<td style='background-color:#FF8080'>Down</td>" -replace "<td>Up</td>","< td style='background-color:#5BCCF3'>Up</td>"
} | Out-File $path
Invoke-Item $path
````
### PSWriteHTML
```PowerShell
Import-Module PSWriteHTML
(Get-Module PSWriteHTML).ExportedCommands
Get-Service | Out-GridHtml -FilePath ~\Desktop\Get-Service-Out-GridHtml.html
````
### HtmlReport
```PowerShell
Import-Module HtmlReport
$ topVM = s | Sort PrivateMemorySize -Descending | Select -First 10 | %{,@(($_.ProcessName + " " + $_.Id), $_.PrivateMemorySize)}
$ top CPU = ps | Sort CPU-Descending | Select -First 10 | %{,@(($_.ProcessName + " " + $_.Id), $_.CPU)}
New-Report -Title "Piggy Processes" -Input {
New-Chart Bar "Top VM Users" -input $topVm
New-Chart Column "Top CPU Overall" -input $topCPU
ps | Select ProcessName, Id, CPU, WorkingSet, *MemorySize | New-Table "All Processes"
} > ~\Desktop\Get-Process-HtmlReport.html
````
# SQLite
```PowerShell
$path = "$home\Documents\Get-Service.db"
$Module = Get-Module MySQLite
if ($Module -eq $null) {
Install-Module MySQLite -Repository PSGallery -Scope CurrentUser
}
Import-Module MySQLite
New-MySQLiteDB -Path $path # створити БД
Invoke-MySQLiteQuery -Path $path -Query "CREATE TABLE Service (Name TEXT NOT NULL, DisplayName TEXT NOT NULL, Status TEXT NOT NULL);" створити таблицю

$Service = Get-Service | select Name,DisplayName,Status
foreach ($S in $Service) {
$Name = $S.Name
$DName = $S.DisplayName
$Status = $S.Status
Invoke-MySQLiteQuery -Path $path -Query "INSERT INTO Service (Name, DisplayName, Status) VALUES ('$Name', '$DName', '$Status');"
}
````
`(Get-MySQLiteDB $path).Tables` список таблиць у базі \
`Invoke-MySQLiteQuery -Path $path -Query "SELECT name FROM sqlite_master WHERE type='table';"` список таблиць в базі \
`Invoke-MySQLiteQuery -Path $path -Query "DROP TABLE Service;"` видалити таблицю
```PowerShell
$TableName = "Service"
Invoke-MySQLiteQuery -Path $path -Query "SELECT * FROM $TableName" # прочитати вміст таблиці (у форматі об'єкта)
````
Get-Service | select Name,DisplayName,Status | ConvertTo-MySQLiteDB -Path $path -TableName Service -force` конвертувати об'єкт у таблицю

### Database password
```PowerShell
$Connection = New-SQLiteConnection -DataSource $path
$Connection.ChangePassword("password")
$Connection.Close()
Invoke-SqliteQuery -Query "SELECT * FROM Service" -DataSource "$path;Password=password"
````
# MySQL

`apt -y install mysql-server mysql-client` \
`mysql -V` \
`systemctl status mysql` \
`mysqladmin -u root password` задати пароль root

`nano /etc/mysql/mysql.conf.d/mysqld.cnf`
````
[mysqld]
user = mysql
# pid-file = /var/run/mysqld/mysqld.pid
# socket = /var/run/mysqld/mysqld.sock
# port = 3306
# datadir = /var/lib/mysql
# tmpdir = /tmp
bind-address = 0.0.0.0
mysqlx-bind-address = 0.0.0.0
log_error = /var/log/mysql/error.log
````
`systemctl restart mysql` \
`ss-tulnp | grep 3306`\
`ufw allow 3306/tcp` \
`nc -zv 192.168.1.253 3306` \
`tnc 192.168.1.253 -p 3306`

`mysql -u root -p` \
`SELECT user(), now(), version();` \
`quit;`

`mysql -u root -p -e 'SHOW TABLES FROM db_aduser;'' відобразити список таблиць без підключення до консолі MySQL

`CREATE` створити БД, користувача, таблицю \
`ALTER` управління стовпцями таблиці \
`DROP` видалити БД, користувача, таблицю \
`USE` вибрати БД \
`SHOW` вивісли список БД, прав доступу користувача (GRANTS), назви стовпців та їх властивості \
`GRANT` дати доступ користувачеві до БД \
`REVOKE` видалити доступ користувача до БД \
`UPDATE` змінити права доступу, значення з таблиці \
`FLUSH` оновити права доступу \
`SELECT` відобразити обрану БД, вивести список користувачів, вибірка даних у таблиці \
`INSERT` внести дані \
`DELETE` видалити дані в (FROM) таблиці

### DATA TYPE

VARCHAR(N) рядок змінної довжини, у форматі ASCII, де один символ займає 1 байт, числом N вказується максимальна можлива довжина рядка \
`NVARCHAR(N)` рядок змінної довжини, у форматі Unicode, де один символ займає 2 байти \
CHAR(N)/nchar(N) рядок фіксованої довжини, яка завжди доповнюється праворуч пробілами до довжини N і в базі даних вона займає рівно N символів \
`INT` ціле число, від -2147483648 до 2147483647, займає 4 байти \
`FLOAT` число, в якому може бути десяткова точка (кома) \
`BIT` прапор, Так - 1 або Ні - 0 \
`DATE` формат дати, наприклад 25.05.2023 \
`TIME` 23:30:55.1234567 \
`DATETIME` 25.05.2023 23:30:55.1234567

### DATABASE
````
SHOW databases; # вивести список БД
CREATE DATABASE db_aduser; # створити БД
CREATE DATABASE db_rep DEFAULT CHARACTER SET utf8 DEFAULT COLLATE utf8_general_ci; # створити БД з кодуванням UTF-8
DROP DATABASE db_rep; видалити БД
USE db_aduser; # вибрати/перейти на обрану БД
SELECT database(); # Відобразити вибрану БД
````
### USER
````
SELECT USER,HOST FROM mysql.user; # вивести список УЗ
CREATE USER posh@localhost IDENTIFIED BY '1qaz!QAZ'; # створити УЗ, яка підключатиметься з локального сервера
CREATE USER posh@localhost IDENTIFIED BY '1qaz!QAZ'; # створити УЗ, яка підключатиметься із зазначеного сервера
CREATE USER posh@'192.168.3.99' IDENTIFIED BY '1qaz!QAZ'; # УЗ для доступу з конкретного сервера
CREATE USER 'admin'@'%' IDENTIFIED BY 'Admin12#'; # УЗ для доступу з будь-якого сервера (% - Wildcard)
DROP USER posh@localhost; # видалити користувача
SHOW GRANTS FOR posh@'%'; # відобразити права доступу користувача
GRANT ALL PRIVILEGES ON db_aduser.* TO posh@'192.168.3.99'; # повний доступ до posh до БД db_aduser
GRANT ALL PRIVILEGES ON *.* TO posh@'%'; доступ до всіх БД з будь-якого клієнтського хоста
GRANT SELECT,DELETE ON mysql.* TO posh@'%'; # права SELECT та DELETE на вбудовану БД mysql
REVOKE DELETE ON mysql.* FROM posh@'%'; # видалити доступ DELETE
UPDATE mysql.user SET super_priv='Y' WHERE USER='posh' AND host='%'; # Змінити привілеї для користувача
SELECT USER,HOST,super_priv FROM mysql.user; # список УЗ та таблиця з правами SUPER privilege
FLUSH PRIVILEGES; # оновити права доступу
````
### TABLE
````
SHOW TABLES; # відобразити список усіх таблиць
SHOW TABLES LIKE '%user'; # Пошук таблиці по wildcard-імені
CREATE TABLE table_aduser (ID INT NOT NULL AUTO_INCREMENT, Name VARCHAR(100), email VARCHAR(100), PRIMARY KEY(ID)); створити таблицю
DROP TABLE table_aduser; видалити таблицю
````
### COLUMN
````
SHOW COLUMNS FROM table_aduser; # Відобразити назву стобців та їх властивості
ALTER TABLE table_aduser DROP COLUMN ID; # видалити стовпець id
ALTER TABLE table_aduser ADD COLUMN info VARCHAR(10); # додати стовпець info
ALTER TABLE table_aduser CHANGE info new_info VARCHAR(100); # змінити ім'я стовпця info на new_info та його тип даних
ALTER TABLE table_aduser ADD COLUMN (ID INT NOT NULL AUTO_INCREMENT, PRIMARY KEY (ID)); # додати стовпець id
````
### INSERT
````
INSERT table_aduser (Name, email) VALUES ('Alex','no-email');
INSERT table_aduser (Name, email) VALUES ('Alex','no-email');
INSERT table_aduser (Name) VALUES ('Support');
INSERT table_aduser (Name) VALUES ('Jack');
````
### SELECT
````
SELECT * FROM table_aduser; # Вміст усіх стовпців у вибраній (FROM) таблиці
SELECT Name, email FROM table_aduser; # Вміст зазначених стовпців
SELECT DISTINCT Name, Email FROM table_aduser; # Відобразити унікальні записи (без повторень)
SELECT * FROM table_aduser ORDER BY Name; відсортувати за Name
SELECT * FROM table_aduser ORDER BY Name DESC; # Зворотнє сортування
SELECT COUNT(*) FROM table_aduser; кількість рядків у таблиці
SELECT COUNT(new_info) FROM table_aduser; кількість рядків у стовпці
````
### WHERE
````
NOT; AND; OR # за пріоритетами умов
SELECT * FROM table_aduser WHERE Name = 'Alex'; пошук за вмістом
SELECT * FROM table_aduser WHERE NOT Name! = 'Alex'; # умова NOT де Name не дорівнює значенню
SELECT * FROM table_aduser WHERE email! = ''; # вивести рядки, де вміст email не рано null
SELECT * FROM table_aduser WHERE email != '' OR id > 1000; # або id вище 1000
SELECT * FROM table_aduser WHERE Name RLIKE "support"; # реєстронезалежний (RLIKE) пошук
SELECT * FROM table_aduser WHERE Name RLIKE "^support"; # починаються тільки з цього словосполучення
````
### DELETE
````
SELECT * FROM table_aduser WHERE Name RLIKE "alex"; знайти і перевірити значення перед видаленням
DELETE FROM table_aduser WHERE Name RLIKE "alex"; # Query OK, 2 rows affected # видалено два рядки
DELETE FROM table_aduser; # видалити ВСІ значення
````
### UPDATE
````
SELECT * FROM table_aduser WHERE Name = 'Jack'; знайти і перевірити значення перед зміною
UPDATE table_aduser SET Name = 'Alex' WHERE Name = 'Jack'; # змінити значення 'Jack' на 'Alex'
UPDATE db_aduser.table_aduser SET Name='BCA' WHERE id=1; # змінити значення у рядку з ID 1
````
### CHECK
````
CHECK TABLE db_aduser.table_aduser; # перевірити
ANALYZE TABLE db_aduser.table_aduser; # аналізувати
OPTIMIZE TABLE db_aduser.table_aduser; # оптимізувати
REPAIR TABLE db_aduser.table_aduser; # відновити
TRUNCATE TABLE db_aduser.table_aduser; # очистити
````
### DUMP
````
mysqldump -u root -p --databases db_aduser > /bak/db_aduser.sql
mysql -u root -p db_aduser < /bak/db_aduser.sql

crontab -e
00 22 * * * /usr/bin/mysqldump -uroot -p1qaz! QAZ db_zabbix | /bin/bzip2 > `date +/dump/zabbix/zabbix-\%d-\%m-\%Y-\%H:\%M.bz2`
00 23 * * * /usr/bin/mysqldump -uroot -p1qaz! `
0 0 * * * find /dump/zabbix -mtime +7 -exec rm {} \;

mysqldump -u root --single-transaction db_zabbix > /dump/zabbix/db_zabbix.sql
mysql -u user_zabbix -p -e 'CREATE DATABASE db_zabbix;'
mysql -u user_zabbix -p db_zabbix < /root/db_zabbix.sql
````
### innodb_force_recovery
````
sed -i '/innodb_force_recovery/d' /etc/mysql/my.cnf # видалити
mode = 6; sed -i "/^\[mysqld\]/{N;s/$/\ninnodb_force_recovery=$mode/}" /etc/mysql/my.cnf # додати mode 6
systemctl restart mysql

[mysqld]
innodb_force_recovery=1 # сервер намагається розпочати роботу незалежно від того, чи є пошкоджені дані InnoDB чи ні
innodb_force_recovery=2 # вдається відновити роботу за рахунок зупинки потоку команд, які були частково виконані або не виконані (не запускає фонові операції)
innodb_force_recovery=3 # скасовує відкат після відновлення пошкоджених файлів (не намагається відкотити транзакції)
innodb_force_recovery=6 # запуск СУБД у режимі read only
````
### MySQL Connector NET

### Add-ADUser
```PowerShell
$ip = "192.168.1.253"
$user = "posh"
$pass = "1qaz!QAZ"
$db = "db_aduser"
Add-Type –Path "$home\Documents\MySQL-Connector-NET\8.0.31-4.8\MySql.Data.dll"
$Connection = [MySql.Data.MySqlClient.MySqlConnection]@{
ConnectionString="server=$ip;uid=$user;pwd=$pass;database=$db"
}
$Connection.Open()
$Command = New-Object MySql.Data.MySqlClient.MySqlCommand
$Command.Connection = $Connection
$UserList = Get-ADUser -filter * -properties name,EmailAddress
foreach ($user in $UserList) {
$uname=$user.Name
$uemail=$user.EmailAddress
$Command.CommandText = "INSERT INTO table_aduser (Name, Email) VALUES ('$uname','$uemail')"
$Command.ExecuteNonQuery()
}
$Connection.Close()
````
### Get-ADUser
```PowerShell
$ip = "192.168.1.253"
$user = "posh"
$pass = "1qaz!QAZ"
$db = "db_aduser"
Add-Type –Path "$home\Documents\MySQL-Connector-NET\8.0.31-4.8\MySql.Data.dll"
$Connection = [MySql.Data.MySqlClient.MySqlConnection]@{
ConnectionString = "server=$ip;uid=$user;pwd=$pass;database=$db"
}
$Connection.Open()
$Command = New-Object MySql.Data.MySqlClient.MySqlCommand
$Command.Connection = $Connection
$MYSQLDataAdapter = New-Object MySql.Data.MySqlClient.MySqlDataAdapter
$MYSQLDataSet = New-Object System.Data.DataSet
$Command.CommandText = "SELECT * FROM table_aduser"
$MYSQLDataAdapter.SelectCommand = $Command
$NumberOfDataSets = $MYSQLDataAdapter.Fill($MYSQLDataSet, "data")
$Collections = New-Object System.Collections.Generic.List[System.Object]
foreach($DataSet in $MYSQLDataSet.tables[0]) {
$Collections.Add([PSCustomObject]@{
Name = $ DataSet.name;
Mail = $DataSet.email
})
}
$Connection.Close()
$Collections
````
# MSSQL

`wget -qO- https://packages.microsoft.com/keys/microsoft.asc | apt-key add - `імпортувати GPG-ключ для репозиторію \
`https://packages.microsoft.com/config/ubuntu/` вибрати репозиторій та скопіювати URL \
`add-apt-repository "$(wget -qO- https://packages.microsoft.com/config/ubuntu/20.04/mssql-server-2019.list)"` \
`apt-get update` оновити список пакетів \
`apt-get install mssql-server` \
`/opt/mssql/bin/mssql-conf setup` скрипт початкової конфігурації (вибрати редакцію, 3 - express та російська мова 9 з 11) \
`systemctl status mssql-server` \
`curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -` встановити клієнт \
`curl https://packages.microsoft.com/config/ubuntu/20.04/prod.list | tee /etc/apt/sources.list.d/msprod.list` \
`apt-get update` \
`apt-get install mssql-tools` \
`echo 'export PATH="$PATH:/opt/mssql-tools/bin"' >> ~/.bashrc` додати в домашній каталог файлу bashrc, щоб не писати шлях до виконуваного файлу \
`export PATH="$PATH:/opt/mssql-tools/bin"` \
`iptables -I INPUT 1 -p tcp --dport 1433 -j ACCEPT`
````
sqlcmd -S localhost -U SA
CREATE DATABASE itinvent
go
SELECT name FROM master.dbo.sysdatabases
go
````
### System.Data.SqlClient
```PowerShell
$user = "itinvent"
$pass = "itinvent"
$db = "itinvent"
$srv = "192.168.3.103"
$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
$SqlConnection.ConnectionString = "server=$srv;database=$db;user id=$user;password=$pass;Integrated Security=false"

$SqlCommand = New-Object System.Data.SqlClient.SqlCommand` клас формату команди
$SqlCommand.CommandText = "SELECT * FROM ITINVENT.dbo.USERS"` відобразити вміст таблиці
#$SqlCommand.CommandText = "SELECT LICENCE_DATE,DESCR,MODEL_NO,TYPE_NO FROM ITINVENT.dbo.ITEMS where LICENCE_DATE IS NOT NULL"
$SqlCommand.Connection = $SqlConnection` передати формат підключення
$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter` створити адаптер підключення для виконання SELECT запитів до БД
$SqlAdapter.SelectCommand = $SqlCommand` передати команду

$DataSet = New-Object System.Data.DataSet` створити об'єкт прийому даних формату XML
$SqlAdapter.Fill($DataSet)` заповнити даними отримані від адаптера (повертає кількість об'єктів)
$SqlConnection.Close()
$Data = $DataSet.Tables
$ Data[0] | ft
````
### SqlClient INSERT
```PowerShell
$user = "itinvent"
$pass = "itinvent"
$db = "db_test"
$srv = "192.168.3.103"
$sql = "INSERT INTO table_test (column_user) VALUES ('lifailon')"` додати дані до таблиці table_test до колонки column_user
$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
$SqlConnection.ConnectionString = "server=$srv;database=$db;user id=$user;password=$pass;Integrated Security=false"
$SqlCommand = New-Object System.Data.SqlClient.SqlCommand
$SqlCommand.CommandText = $sql
$SqlCommand.Connection = $SqlConnection
$SqlConnection.Open()
$rowsAffected = $SqlCommand.ExecuteNonQuery();` для запитів INSERT/UPDATE/DELETE не використовується SqlDataAdapter
$SqlConnection.Close()
````
### SSMS INSERT
````
USE [db_test]
GO
INSERT INTO [dbo].[table_test]
([column_user])
VALUES
('lifailon')
GO
SELECT TOP (1000) [column_user]
FROM [db_test].[dbo].[table_test]
````
### T-SQL

- DDL (Data Definition Language/Мова визначення даних). До цього типу належать команди, які створюють базу даних, таблиці, індекси, процедури, що зберігаються. \
`CREATE` створює об'єкти бази даних (саму базу даних, таблиці, індекси тощо) \
`ALTER` змінює об'єкти бази даних \
`DROP` видаляє об'єкти бази даних \
`TRUNCATE` видаляє всі дані з таблиць

- DML (Data Manipulation Language/Мова маніпуляції даними). До цього типу відносять команди з вибору, оновлення, додавання та видалення даних. \
`SELECT` отримує дані з БД \
`UPDATE` оновлює дані \
`INSERT` додає нові дані \
`DELETE` видаляє дані

- DCL (Data Control Language/Мова керування доступу до даних). До цього типу відносять команди, які керують правами доступу до даних. \
`GRANT` надає права для доступу до даних \
`REVOKE` відкликає права на доступ до даних
````
- Змінні
DECLARE @text NVARCHAR(20), @int INT;
SET @text = 'Test';
SET @ int = 21;
select @text,@int

-- Імена сервера та екземпляра
Select @@SERVERNAME as [Server\Instance];

-- версія SQL Server
Select @@VERSION як SQLServerVersion;

-- Поточна БД (БД, у контексті якої виконується запит)
Select DB_NAME() AS CurrentDB_Name;

-- Час роботи з моменту запуску сервера
SELECT @@Servername AS ServerName ,
create_date AS ServerStarted ,
DATEDIFF(s, create_date, GETDATE()) / 86400.0 AS DaysRunning ,
DATEDIFF(s, create_date, GETDATE()) AS SecondsRunnig
FROM sys.databases
WHERE name = 'tempdb';

-- Кількість активних з'єднань
SELECT @@Servername AS Server ,
DB_NAME(database_id) AS DatabaseName ,
COUNT(database_id) AS Connections ,
Login_name AS LoginName ,
MIN(Login_Time) AS Login_Time ,
MIN(COALESCE(last_request_end_time, last_request_start_time))
AS Last_Batch
FROM sys.dm_exec_sessions
WHERE database_id > 0
AND DB_NAME(database_id) NOT IN ( 'master', 'msdb' )
GROUP BY database_id ,
login_name
ORDER BY DatabaseName;

-- Статус Backup
SELECT @@Servername AS ServerName ,
d.Name AS DBName ,
MAX(b.backup_finish_date) AS LastBackupCompleted
FROM sys.databases d
LEFT OUTER JOIN msdb..backupset b
ON b.database_name = d.name
AND b.[type] = 'D'
GROUP BY d.Name
ORDER BY d.Name;

- Шлях до Backup
SELECT @@Servername AS ServerName ,
d.Name AS DBName ,
b.Backup_finish_date ,
bmf.Physical_Device_name
FROM sys.databases d
INNER JOIN msdb..backupset b ON b.database_name = d.name
AND b.[type] = 'D'
INNER JOIN msdb.dbo.backupmediafamily bmf ON b.media_set_id = bmf.media_set_id
ORDER BY d.NAME ,
b.Backup_finish_date DESC;

-- Вивести список всіх БД, моделі відновлення та шлях до mdf/ldf
EXEC sp_helpdb;
SELECT @@SERVERNAME AS Server,
d.name AS DBName ,
create_date ,
recovery_model_Desc AS RecoveryModel ,
m.physical_name AS FileName
FROM sys.databases d
JOIN sys.master_files m ON d.database_id = m.database_id
ORDER BY d.name;

-- Розмір БД
with fs
as
(
select database_id, type, size * 8.0 / 1024 size
from sys.master_files
)
select
name,
(select sum(size) fs fs where type = 0 and fs.database_id = db.database_id) DataFileSizeMB,
(select sum(size) fs fs where type = 1 and fs.database_id = db.database_id) LogFileSizeMB
від sys.databases

-- Пошук таблиці за маскою імені (висновок: назви схеми де знаходиться об'єкт, тип об'єкта, дата створення та останньої модифікації):
select [object_id], [schema_id],
	schema_name([schema_id]) as [schema_name],
	[name],
	[type],
	[type_desc],
	[create_date],
	[modify_date]
від sys.all_objects
-- where [name]='INVENT';
where [name] like '%INVENT%';

-- Кількість рядків у таблицях
SELECT @@ServerName AS Server ,
DB_NAME() AS DBName ,
OBJECT_SCHEMA_NAME(p.object_id) AS SchemaName ,
OBJECT_NAME(p.object_id) AS TableName ,
i.Type_Desc ,
i.Name AS IndexUsedForCounts ,
SUM(p.Rows) AS Rows
FROM sys.partitions p
JOIN sys.indexes i ON i.object_id = p.object_id
AND i.index_id = p.index_id
WHERE i.type_desc IN ( 'CLUSTERED', 'HEAP' )
-- Цей ключ (1 index per table)
AND OBJECT_SCHEMA_NAME(p.object_id) <> 'sys'
GROUP BY p.object_id ,
i.type_desc ,
i.Name
ORDER BY SchemaName ,
TableName;

-- Знайти строкове (nvarchar) значення 2023 за всіма таблицями бази даних
-- Відображається в якій таблиці та стовпці зберігається значення, а також кількість знайдених пари таблиця-колонка
set nocount on
declare @name varchar(128), @substr nvarchar(4000), @column varchar(128)
set @substr = '%2023%'
declare @sql nvarchar(max);
create table`rslt
(table_name varchar(128), field_name varchar(128), [value] nvarchar(max))
declare s cursor for select table_name as table_name from information_schema.tables where table_type = 'BASE TABLE' order by table_name
open s
fetch next from s into @name
while @@fetch_status = 0
begin
declare c cursor for
select quotename(column_name) as column_name from information_schema.columns
where data_type in ('text', 'ntext', 'varchar', 'char', 'nvarchar', 'char', 'sysname', 'int', 'tinyint') and table_name = @name
set @name = quotename(@name)
open c
fetch next from c into @column
while @@fetch_status = 0
begin
--print 'Processing table - ' + @name + ', column - ' + @column
set @sql='insert into`rslt select ''' + @name + ''' as Table_name, ''' + @column + ''', cast(' + @column +
' as nvarchar(max)) from' + @name + ' where cast(' + @column + ' as nvarchar(max)) like ''' + @substr + '''';
print @sql;
exec(@sql);
fetch next from c into @column;
end
close c
deallocate c
fetch next from s into @name
end
select table_name as [Table Name], field_name as [Field Name], count(*) as [Found Mathes] from`rslt
group by table_name, field_name
order by table_name, field_name
drop table`rslt
close s
deallocate s

-- Пошук у таблиці [CI_HISTORY] та стовпчику [HIST_ID]:
SELECT * FROM ITINVENT.dbo.CI_HISTORY where [HIST_ID] like '%2023%';

-- Дізнатися про фрагментацію індексів
DECLARE @db_id SMALLINT;
SET @db_id = DB_ID(N'itinvent');
IF @db_id IS NULL
BEGIN;
PRINT N'Неправильне ім'я бази';
END;
ELSE
BEGIN;
	SELECT
		object_id AS [ID об'єкта],
		index_id AS [ID індексу],
		index_type_desc AS [Тип індексу],
		avg_fragmentation_in_percent AS [Фрагментація у %]
		
	FROM sys.dm_db_index_physical_stats(@db_id, NULL, NULL, NULL , 'LIMITED')
	 
	ORDER BY [avg_fragmentation_in_percent] DESC;
END;
GO

-- TempDB
-- Initial size - початковий/мінімальний розмір БД (1024 МБ)
-- Autogrowh - приріст (512MB)
-- За замовчуванням tempdb налаштована на авто-розширення (Autogrow) і при кожному перезавантаженні SQL Server перетворює файли цієї бази даних з мінімальним розміром ініціалізації.
-- Збільшивши розмір ініціалізації файлів tempdb, можна мінімізувати витрати системних ресурсів на операції авто-розширення.

-- Змінити шлях до БД:
USE master;
GO
ALTER DATABASE tempdb
MODIFY FILE (NAME = tempdev, FILENAME = 'F:\tempdb.mdf');
GO
ALTER DATABASE tempdb
MODIFY FILE (NAME = temp2, FILENAME = 'F:\tempdb_mssql_2.ndf');
GO
ALTER DATABASE tempdb
MODIFY FILE (NAME = temp3, FILENAME = 'F:\tempdb_mssql_3.ndf');
GO
ALTER DATABASE tempdb
MODIFY FILE (NAME = temp4, FILENAME = 'F:\tempdb_mssql_4.ndf');
GO
ALTER DATABASE tempdb
MODIFY FILE (NAME = temp5, FILENAME = 'F:\tempdb_mssql_5.ndf');
GO
ALTER DATABASE tempdb
MODIFY FILE (NAME = temp6, FILENAME = 'F:\tempdb_mssql_6.ndf');
GO
ALTER DATABASE tempdb
MODIFY FILE (NAME = temp7, FILENAME = 'F:\tempdb_mssql_7.ndf');
GO
ALTER DATABASE tempdb
MODIFY FILE (NAME = temp8, FILENAME = 'F:\tempdb_mssql_8.ndf');
GO
ALTER DATABASE tempdb
MODIFY FILE (NAME = templog, FILENAME = 'F:\templog.ldf');
GO

-- Вказати розмір файлу:
MODIFY FILE (NAME = temp2, FILENAME = 'F:\tempdb_mssql_2.ndf', SIZE = 1048576KB, FILEGROWTH = 524288KB);
````
### Тип резервної копії

- Full (Повна копія). Коли стартує повне резервування, записується Log Sequence Number (LSN - послідовний номер журналу), а також LSN записується і при завершенні повного резервування. Цей LSN є механізмом, який використовується SQL Server, щоб знати, в якому порядку виконувались оператори INSERT, UPDATE або DELETE. При цьому наявність записаних LSN початку та закінчення як частини повного бекапу забезпечує узгоджене з точки зору транзакцій резервне копіювання, оскільки при повному резервному копіюванні враховуються зміни, що відбулися під час резервного копіювання. Це забезпечує обробку таких транзакцій у процесі відновлення бекапу.
- Differential (диференційна / різницева копія). Зберігає дані, що змінилися після останньої Повної резервної копії. При відновленні потрібно спочатку відновити Повну резервну копію в режимі NORECOVERY, потім можна застосувати будь-яку з наступних копій, без попередньої Повної резервної копії Різна копія марна. Кожна наступна копія буде зберігати всі дані, що входять до попередньої резервної копії, зроблену після попередньої повної копії.
- Incremental (інкрементальна/копія журналів транзакцій). Резервне копіювання журналу транзакцій копіює всі транзакції, що відбулися з моменту останнього резервного копіювання, а потім урізує журнал транзакцій для звільнення дискового простору. Транзакції відбуваються у порядку (LSN), бэкап журналу підтримує цей порядок транзакцій. Бекапи журналів транзакцій мають поновлюватися по порядку. Для відновлення бази даних буде потрібно весь ланцюжок резервних копій: повний і всі наступні інкрементальні журнали транзакцій.

### Моделі відновлення

- Simple (Проста). Зберігається лише необхідний життя залишок журналу транзакцій. Журнал транзакцій (лог) автоматично очищується. Створення резервних копій журналу транзакцій неможливе, тому залишається найбільш обмежена кількість опцій відновлення. Недоступний функціонал: Always On, Point-In-Time відновлення, Резервні копії журналу транзакцій.
- Full (Повна). Зберігається журнал транзакцій всіх змін до БД з останнього резервного копіювання журналу транзакцій. Журнал транзакцій не очищатиметься доти, доки не буде зроблено резервну копію журналу транзакцій.
- Bulk logged (З неповним протоколюванням). Ідентична Full, за винятком: SELECT INTO, BULK INSERT та BCP, INSERT INTO SELECT, операції з індексами (CREATE INDEX, ALTER INDEX REBUILD, DROP INDEX)

### Системні БД

- Master. Зберігаються всі дані системного рівня (конфігурація системи, відомості про облікові записи входу, інформація про всі інші бази даних) для екземпляра SQL Server.
- Tempdb. Робочий простір для тимчасових об'єктів, таких як глобальні або локальні тимчасові таблиці, тимчасові збережені процедури, табличні змінні та курсори. Перетворюється під час кожного запуску SQL Server.
- Модель. Використовується як шаблон для всіх баз даних, що створюються в екземплярі SQL Server, весь вміст бази даних model, включаючи параметри бази даних, копіюється у створену базу даних. Оскільки база даних tempdb створюється щоразу під час запуску SQL Server, база даних model завжди має існувати у системі SQL Server.
- msdb. Використовується агентом SQL Server для створення розкладу попереджень (оператор) та виконання завдань, а також іншими компонентами. SQL Server зберігає повний журнал резервного копіювання та відновлення у базі даних msdb. Для надсилання пошти оператору використовується: USE [msdb].
- Resource. Доступна лише для читання база даних, що містить усі системні об'єкти, наприклад sys.objects, фізично зберігаються у базі даних resource, але логічно присутні у схемі sys кожної бази даних.

### Регламентні операції

- Перевірка цілісності бази даних

`DBCC CHECKDB`

- Індекси. Індекси використовуються для швидкого пошуку даних без необхідності пошуку/перегляду всіх рядків у таблиці баз даних при кожному зверненні до таблиці баз даних. Індекс прискорює процес запиту, надаючи швидкий доступ до рядків даних у таблиці, аналогічно до того, як покажчик у книзі допомагає вам швидко знайти необхідну інформацію. Індекси надають шлях для швидкого пошуку даних на основі значень цих стовпців. До кожного індексу обов'язково зберігається його статистика. MS SQL Server самостійно створює та змінює індекси під час роботи з базою. З часом дані у індексі стають фрагментованими, тобто. розкиданими за базою даних, що серйозно знижує продуктивність запитів. Якщо фрагментація становить від 5 до 30% (стандартно в завданні 15%), то рекомендується її усунути за допомогою реорганізації, при фрагментації вище 30% (за замовчуванням у задачі > 30% фрагментації та кількість сторінок > 1000) необхідне повне перестроювання індексів. Після перебудови планово використовується лише реорганізація.

- Реорганізація або дефрагментація індексу – це серія невеликих локальних переміщень сторінок так, щоб індекс не був фрагментований. Після реорганізації статистика не оновлюється. Під час виконання майже всі дані доступні, користувачі можуть працювати.

`sp_msforeachtable N'DBCC INDEXDEFRAG (<ім'я бази даних>, ''?'')'`

- Перебудова (Rebuild) індексів (або завдання у майстрі планів обслуговування: Відновити індекс) запускає процес повної побудови індексів. У версії MS SQL Server Standard відбувається відключення всіх клієнтів від бази під час виконання операції. Після перебудови обов'язково оновлюється статистика.

`sp_msforeachtable N'DBCC DBREINDEX (''?'')'`

- Оновлення статистики. Статистика - невелика таблиця (зазвичай до 200 рядків), в якій зберігається узагальнена інформація про те, які значення та як часто зустрічаються в таблиці. На підставі статистики сервер приймає рішення, як краще збудувати запит. Коли відбуваються запити до БД (наприклад, SELECT), ви отримуєте дані, але не описуєте те, як ці дані повинні бути вилучені. В отриманні та обробці даних допомагає статистика. Під час виконання процедури поновлення статистики дані не блокуються.

`exec sp_msforeachtable N'UPDATE STATISTICS? WITH FULLSCAN''

- Очищення процедурного кешу виконується після оновлення статистики. Оптимізатор MS SQL Server кешує плани запитів їхнього повторного виконання. Це робиться для того, щоб заощаджувати час, що витрачається на компіляцію запиту в тому випадку, якщо такий запит вже виконувався і його план відомий. Після оновлення статистики, не буде очищено процедурний кеш, SQL Server може вибрати старий (неоптимальний) план запиту з кешу замість того, щоб побудувати новий (більш оптимальний) план.

`DBCC FREEPROCCACHE`

# InfluxDB

[Download InfluxDB 1.x Open Source](https://www.influxdata.com/downloads)
[InfluxDB-Studio](https://github.com/CymaticLabs/InfluxDBStudio)

### Install Windows
```PowerShell
Invoke-RestMethod "https://dl.influxdata.com/influxdb/releases/influxdb-1.8.10_windows_amd64.zip" -OutFile "$home\Downloads\influxdb-1.8.10_windows_amd64.zip"
Expand-Archive "$home\Downloads\influxdb-1.8.10_windows_amd64.zip" -DestinationPath "$home\Documents\"
Remove-Item "$home\Downloads\influxdb-1.8.10_windows_amd64.zip"
& "$home\Downloads\influxdb-1.8.10-1\influxd.exe"
````
### Install Ubuntu
``` Bash
wget https://dl.influxdata.com/influxdb/releases/influxdb_1.8.10_amd64.deb
sudo dpkg -i influxdb_1.8.10_amd64.deb
systemctl start influxdb
systemctl status influxdb

ps aux | grep influxdb grep -Ev "grep"
Netstat-Natpl | grep 80[8-9][3-9]
````
### API
``` Bash
nano /etc/influxdb/influxdb.conf

[http]
enabled = true
bind-address = ":8086"
auth-enabled = false

systemctl restart influxdb
````
### Chronograf
````
wget https://dl.influxdata.com/chronograf/releases/chronograf-1.10.2_windows_amd64.zip -UseBasicParsing -OutFile chronograf-1.10.2_windows_amd64.zip
Expand-Archive .\chronograf-1.10.2_windows_amd64.zip -DestinationPath 'C:\Program Files\InfluxData\chronograf\'

wget https://dl.influxdata.com/chronograf/releases/chronograf_1.10.2_amd64.deb
sudo dpkg -i chronograf_1.10.2_amd64.deb
systemctl status influxdb
http://192.168.3.102:8888
````
### Grafana

[Download](https://grafana.com/grafana/download)

`invoke-RestMethod https://dl.grafana.com/enterprise/release/grafana-enterprise-10.3.1.windows-amd64.msi -OutFile "$home\Download\grafana.msi"`
``` Bash
apt-get install -y adduser libfontconfig1 musl
wget https://dl.grafana.com/enterprise/release/grafana-enterprise_10.3.1_amd64.deb
dpkg -i grafana-enterprise_10.3.1_amd64.deb
systemctl start grafana-server
systemctl status grafana-server
````
### CLI Client

`apt install influxdb-client` \
`influx` \
`influx --host 192.168.3.102 --username admin --password password`
```PowerShell
$influx_client_exec = "$home\Documents\influxdb-1.8.10-1\influx.exe"
& $influx_client_exec -host 192.168.3.102 -port 8086
help
show databases
use PowerShell
SELECT * FROM "HardwareMonitor" WHERE time > now() - 5m
````
### USERS

`SHOW USERS` відобразити користувачів та їх права доступу \
`CREATE USER admin WITH PASSWORD 'password' WITH ALL PRIVILEGES` створити користувача \
`GRANT ALL PRIVILEGES TO "admin"` надати права доступу \
`GRANT READ ON "database" TO "admin"` доступ на читання для БД або запис (WRITE) \
`REVOKE ALL PRIVILEGES FROM "admin"` відкликати права доступу \
`SHOW GRANTS FOR "admin"` БД та привілеї доступу для вказаного користувача \
`SET PASSWORD FOR "admin" = 'new_password'` змінити пароль \
`DROP USER "admin"` видалити користувача

### DATABASE

`CREATE DATABASE powershell` створити БД \
`SHOW DATABASES` відобразити список БД \
`DROP DATABASE powershell` видалити БД \
`USE powershell` \
`SHOW measurements` відобразити всі таблиці \
`INSERT performance,host=console,counter=CPU value=0.88` записати дані в таблицю performance

### MEASUREMENT

`SHOW TAG KEYS FROM "HardwareMonitor"` відобразити всі теги в таблиці \
`SHOW TAG VALUES FROM "HardwareMonitor" WITH KEY = "HardwareName"` відобразити всі значення вказаного тега \
`SHOW FIELD KEYS FROM "HardwareMonitor"` відобразити всі Field Tags та їх тип даних \
`SHOW SERIES FROM "HardwareMonitor"` відобразити список усіх унікальних серій у вказаній таблиці. Серія - це набір точок даних, які мають однакові значення всім тегів, крім часу. \
`DROP SERIES FROM "HardwareMonitor"` очистити всі дані в таблиці \
`DROP MEASUREMENT "HardwareMonitor"` видалити таблицю

### SELECT/WHERE

`SELECT * FROM performance` відобразити всі дані в таблиці \
`SELECT value FROM performance` відфільтрувати по стовпцю value (тільки Field Keys) \
`SELECT * FROM performance limit 10` відобразити 10 одиниць даних \
`SELECT * FROM performance WHERE time > now() -2d` відобразити дані за останні 2 дні \
`SELECT * FROM performance WHERE time > now() +3h -5m` дані за останні 5 хвилин (+3 години від поточного часу за UTC 0 -5 хвилин) \
`SELECT * FROM performance WHERE counter = 'CPU'` вибірка за тегом \
`SELECT upload/1000 FROM speedtest WHERE upload/1000 <= 250` вибірка по стовпцю upload та розділити висновок на 1000, вивести upload менше 250 \
`DELETE FROM performance WHERE time > now() -1h` видалити дані за останні 1/4 години \
`DELETE FROM performance WHERE time < now() -24h` видалити дані старше 24 годин

### REGEX

`SELECT * FROM "win_pdisk" WHERE instance =~/.*C:/ and time > now() - 5m` і \
`SELECT * FROM "win_pdisk" WHERE instance =~/.*E:/ or instance =~ /.*F:/` або \
`SELECT * FROM "win_pdisk" WHERE instance !~ /.*Total/` не дорівнює (виключити) \
`SELECT * FROM "HardwareMonitor" WHERE time > now() - 5m and HardwareName =~ /Intel/` приблизно дорівнює \
`SELECT * FROM "HardwareMonitor" WHERE time > now() - 5m and HardwareName =~ /Intel.+i7/` еквівалент 12th_Gen_Intel_Core_i7-1260P \
`SELECT * FROM "HardwareMonitor" WHERE time > now() - 5m and HardwareName =~ /^Intel/` починається на Intel \
`SELECT * FROM "HardwareMonitor" WHERE time > now() - 5m and HardwareName =~ /00$/` закінчується на 00

### GROUP BY tag_key

`SELECT * FROM "HardwareMonitor" WHERE time > now() - 5m and SensorName = 'Temperature' GROUP BY HardwareName` створити унікальні групи за тегом HardwareName \
`SELECT * FROM "HardwareMonitor" WHERE time > now() - 5m and SensorName = 'Temperature' GROUP BY Host, HardwareName` більше груп по двох тегах

### Functions(field_key)

[Functions](https://docs.influxdata.com/influxdb/v1.8/query_language/functions)

`SELECT instance,LAST(Avg._Disk_Read_Queue_Length) FROM "win_pdisk" GROUP BY instance` відфільтрувати висновок за останнім/поточним значенням \
`SELECT instance,FIRST(Avg._Disk_Read_Queue_Length) FROM "win_pdisk" GROUP BY instance` відфільтрувати висновок за першим значенням за весь або вказаний відрізок часу \
`SELECT instance,MIN(Avg._Disk_Read_Queue_Length) FROM "win_pdisk" GROUP BY instance` відфільтрувати висновок з відображенням мінімального значення \
`SELECT instance,MAX(Avg._Disk_Read_Queue_Length) FROM "win_pdisk" GROUP BY instance` відфільтрувати висновок з відображенням максимального значення \
`SELECT SUM(Bytes_Received_persec) FROM "win_net" GROUP BY instance` сумах всіх значень \
`SELECT COUNT(Bytes_Received_persec) FROM "win_net" WHERE Bytes_Received_persec >= 0 GROUP BY instance` кількість даних, де значення вище або дорівнює 0 \
`SELECT MEAN(Bytes_Received_persec) FROM "win_net" WHERE Bytes_Received_persec < 1000 GROUP BY instance` середнє значення даних з показником від 0 до 1000 (509)

`SELECT *,MAX(Value) FROM "HardwareMonitor" WHERE time > now() -1h GROUP BY SensorName,Host` створити групи для виявлення максимального значення значення стібка Value кожного тега SensorName та хоста за останню годину \
`SELECT *,MAX(Value) FROM "HardwareMonitor" WHERE time > now() -1h and SensorName = 'CPU_Package' GROUP BY Host` максимальне значення CPU_Package за останню годину для кожного хоста \
`SELECT MEAN(Value) FROM "HardwareMonitor" WHERE time > now() -1h and SensorName = 'CPU_Package' GROUP BY Host` середнє значення CPU_Package за останню годину

### POLICY

`CREATE DATABASE PowerShell WITH DURATION 48h REPLICATION 1 NAME "del2d"` створити БД з політикою зберігання 2 дні \
`CREATE RETENTION POLICY del2h ON powershell DURATION 2h REPLICATION 1` створити нову політику зберігання для БД \
`CREATE RETENTION POLICY del6h ON PowerShell DURATION 6h REPLICATION 1 SHARD DURATION 2h` вказати період зберігання 6 годин + 2 години до очищення (за замовчуванням 1год або більше) \
`ALTER RETENTION POLICY del6h ON powershell DEFAULT` змінити (ALTER) політику зберігання для БД на del6h (DEFAULT) \
`DROP RETENTION POLICY del2d ON powershell` видалення політики зберігання призводить до безповоротного видалення всіх вимірювань (таблиць) та даних, що зберігаються в політиці зберігання \
`SHOW RETENTION POLICIES ON PowerShell` відобразити чинні політики бази даних PowerShell
```PowerShell
$data = Invoke-RestMethod http://192.168.3.102:8086/query?q="SHOW RETENTION POLICIES ON PowerShell"
$col = $data.results.series.columns
$val = $data.results.series.values
$mass = @()
$mass += [string]$col
foreach ($v in $val) {
	$mass += [string]$v
}
$mass = $mass -replace '^','"'
$mass = $mass -replace '$','"'
$mass = $mass -replace '\s','","'
$mass | ConvertFrom-Csv
````
### API POST

Замість таблиць у InfluxDB є виміри. Замість стовпців у ній є теги та поля.
````
Table Tag (string/int) Field (double/int) TIMESTAMP
measurement,Tag_Keys1=Tag_Values1,Tag_Keys2=Tag_Values2 Field_Keys1="Values",Field_Keys2="Values" 000000000000000000
1 2 3

$ip = "192.168.3.104"
$port = "8086"
$db = "powershell"
$table = "speedtest"
$ipp = $ip+":"+$port
$url = "http://$ipp/write?db=$db"
$user = "admin"
$pass = "password" | ConvertTo-SecureString -AsPlainText -Force
$cred = [System.Management.Automation.PSCredential]::new($user,$pass)
$unixtime = (New-TimeSpan -Start (Get-Date "01/01/1970") -End (Get-Date)).TotalSeconds
$timestamp = ([string]$unixtime -replace "\..+") + "000000000"

Invoke-RestMethod -Method POST -Uri $url -Body "$table,host=$(hostname) download=200000,upload=300000,ping=3 $timestamp"
````
### API GET

`curl http://192.168.3.104:8086/query --data-urlencode "q=SHOW DATABASES"` pwsh7 (ConvertFrom-Json) and bash

`$dbs = irm "http://192.168.3.104:8086/query?q=SHOW DATABASES"` \
`$dbs = irm "http://192.168.3.104:8086/query?epoch=ms&u=admin&p=password&q=SHOW DATABASES"` \
`$dbs.results.series.values`
```PowerShell
$ip = "192.168.3.104"
$port = "8086"
$db = "powershell"
$table = "speedtest"
$query = "SELECT * FROM $table"
$ipp = $ip+":"+$port
$url = "http://$ipp/query?db=$db&q=$query"
$data = Invoke-RestMethod -Method GET -Uri $url` -Credential $cred
$data.results.series.name ` ім'я таблиці
$data.results.series.columns` стовпці/ключі
$data.results.series.values ` дані рядково
````
### Endpoints
https://docs.influxdata.com/influxdb/v1.7/tools/api/
```PowerShell
$stats = irm http://192.168.3.104:8086/debug/vars` статистика сервера
$stats."database:powershell".values` у таблицях до БД
$stats.queryExecutor.values` кількість query-запитів (звернень до endpoint /query)
$stats.write.values` кількість write-запитів
$stats.system.uptime
````
`http://192.168.3.104:8086/debug/requests` у клієнтських HTTP-запитах до кінцевих точок /writeи /query \
`http://192.168.3.104:8086/debug/pprof` \
`http://192.168.3.104:8086/ping` \
`http://192.168.3.104:8086/query` \
`http://192.168.3.104:8086/write`

`http://192.168.3.99:8086/api/v2/setup` \
`http://192.168.3.99:8086/api/v2/config` \
`http://192.168.3.99:8086/api/v2/write`

### PingTo-InfluxDB
```PowerShell
while ($ true) {
	$tz = (Get-TimeZone).BaseUtcOffset.TotalMinutes
	$unixtime = (New-TimeSpan -Start (Get-Date "01/01/1970") -End ((Get-Date).AddMinutes(-$tz))).TotalSeconds` -3h UTC
	$timestamp = ([string]$unixtime -replace "\..+") + "000000000"
	$tnc = tnc 8.8.8.8
	$Status = $tnc.PingSucceeded
	$RTime = $tnc.PingReplyDetails.RoundtripTime
	Invoke-RestMethod -Method POST -Uri "http://192.168.3.104:8086/write?db=powershell" -Body "ping,host=$(hostname) status=$status,rtime=$RTime $timestamp"
	sleep 1
}
````
`SELECT * FROM ping WHERE status = false`

### PerformanceTo-InfluxDB
```PowerShell
function ConvertTo-Encoding ([string]$From, [string]$To) {
Begin {
$encFrom = [System.Text.Encoding]::GetEncoding($from)
$encTo = [System.Text.Encoding]::GetEncoding($to)
}
Process {
$bytes = $encTo.GetBytes($_)
$bytes = [System.Text.Encoding]::Convert($encFrom, $encTo, $bytes)
$encTo.GetString($bytes)
}
}

$localization = (Get-Culture).LCID` поточна локалізація
if ($localization -eq 1049) {
	$performance = "\\$(hostname)\Процесор(_Total)\% завантаженості процесора" | ConvertTo-Encoding UTF-8 windows-1251` декодувати кирилицю
} else {
	$performance = "\Processor(_Total)\% Processor Time"
}

$tz = (Get-TimeZone).BaseUtcOffset.TotalMinutes
while ($ true) {
	$unixtime = (New-TimeSpan -Start (Get-Date "01/01/1970") -End ((Get-Date).AddMinutes(-$tz))).TotalSeconds` -3h UTC
	$timestamp = ([string]$unixtime -replace "\..+") + "000000000"
	[double]$value = (Get-Counter $performance).CounterSamples.CookedValue.ToString("0.00").replace(",",".")` округлити тип даних Double
	Invoke-RestMethod -Method POST -Uri "http://192.168.3.104:8086/write?db=powershell" -Body "performance,host=$(hostname),counter=CPU value=$value $timestamp"
	sleep 5
}
````
### Service
```PowerShell
$powershell_Path = (Get-Command powershell).Source
$NSSM_Path = "C:\NSSM\NSSM-2.24.exe"
$Script_Path = "C:\NSSM\PerformanceTo-InfluxDB.ps1"
$Service_Name = "PerformanceTo-InfluxDB"
& $NSSM_Path install $Service_Name $powershell_Path -ExecutionPolicy Bypass -NoProfile -f $Script_Path
Get-Service $Service_Name | Start-Service
Get-Service $Service_Name | Set-Service -StartupType Automatic
````
# Telegraf

Plugins: https://docs.influxdata.com/telegraf/v1.27/plugins/#input-plugins

`iwr https://dl.influxdata.com/telegraf/releases/telegraf-1.27.1_windows_amd64.zip -UseBasicParsing -OutFile telegraf-1.27.1_windows_amd64.zip` \
`Expand-Archive .\telegraf-1.27.1_windows_amd64.zip -DestinationPath "C:\Telegraf"` \
`rm telegraf-1.27.1_windows_amd64.zip` \
`cd C:\Telegraf` \
`.\telegraf.exe -sample-config --input-filter cpu:mem:dns_query --output-filter influxdb > telegraf_nt.conf` створити конфігурацію з виборними плагінами для збору метрик \
`Start-Process notepad++ C:\Telegraf\telegraf_nt.conf`
````
[[outputs.influxdb]]
urls = ["http://192.168.3.104:8086"]
database = "telegraf_nt"
username = "user"
password = "pass"
[[inputs.cpu]]
percpu = false
totalcpu = true
[[inputs.dns_query]]
servers = ["8.8.8.8"]
network = "udp"
domains = ["."]
record_type = "A"
port = 53
timeout = "2s"
````
`.\telegraf.exe --test -config C:\Telegraf\telegraf_nt.conf` тест конфігурації (отримання метрик з виведенням у консоль) \
`C:\Telegraf\telegraf.exe -config C:\Telegraf\telegraf_nt.conf` запустити telegraf (тест відправки даних) \
`.\telegraf.exe --config "C:\Telegraf\telegraf_nt.conf" --service install` створити службу \
Get-Service telegraf | Start-Service`\
`.\telegraf.exe --service uninstall`

`USE telegraf` \
`SELECT usage_idle,usage_system,usage_user FROM cpu`

# Elasticsearch

`Install-Module -Name Elastic.Console -AllowPrerelease` https://github.com/elastic/powershell/blob/master/Elastic.Console/README.md \
`Get-Command -Module Elastic.Console` \
`Get-ElasticsearchVersion` \
`Set-ElasticsearchVersion 7.3.0` \
`Invoke-Elasticsearch` REST API запити

# CData

https://www.powershellgallery.com/profiles/CData \
https://www.cdata.com/kb/tech/elasticsearch-ado-powershell.rst

`Install-Module ElasticsearchCmdlets` https://www.powershellgallery.com/packages/ElasticsearchCmdlets/23.0.8565.1 \
`Import-Module ElasticsearchCmdlets` \
`Get-Command -Module ElasticsearchCmdlets`
```PowerShell
$elasticsearch = Connect-Elasticsearch -Server "$Server" -Port "$Port" -User "$User" -Password "$Password"
$shipcity = "New York"
$orders = Select-Elasticsearch -Connection $elasticsearch -Table "Orders" -Where "ShipCity = ``$ShipCity`'"` пошук та отримання даних
$orders = Invoke-Elasticsearch -Connection $elasticsearch -Query 'SELECT * FROM Orders WHERE ShipCity = @ShipCity' -Params @{'@ShipCity'='New York'}` SQL запити
````
### ADO.NET Assembly

`Install-Package CData.Elasticsearch` https://www.nuget.org/packages/CData.Elasticsearch \
`[Reflection.Assembly]::LoadFile("C:\Program Files\PackageManagement\NuGet\Packages\CData.Elasticsearch.23.0.8565\lib\net40\System.Data.CData.Elasticsearch.dll")`
```PowerShell
$connect = New-Object System.Data.CData.Elasticsearch.ElasticsearchConnection("Server=127.0.0.1;Port=9200;User=admin;Password=123456;")
$connect.Open()
$sql = "SELECT OrderName, Freight from Orders"
$da = New-Object System.Data.CData.Elasticsearch.ElasticsearchDataAdapter($sql, $conn)
$dt = New-Object System.Data.DataTable
$da.Fill($dt)
$dt.Rows | foreach {
Write-Host $_.ordername $_.freight
}
````
### UPDATE
```PowerShell
Update-Elasticsearch -Connection $Elasticsearch -Columns @('OrderName','Freight') -Values @('MyOrderName', 'MyFreight') -Table Orders -Id "MyId"

$cmd = New-Object System.Data.CData.Elasticsearch.ElasticsearchCommand("UPDATE Orders SET ShipCity='New York' WHERE Id = @myId", $conn)
$cmd.Parameters.Add(new System.Data.CData.Elasticsearch.ElasticsearchParameter("@myId","10456255-0015501366"))
$cmd.ExecuteNonQuery()
````
### INSERT
```PowerShell
Add-Elasticsearch -Connection $Elasticsearch -Table Orders -Columns @("OrderName", "Freight") -Values @("MyOrderName", "MyFreight")

$cmd = New-Object System.Data.CData.Elasticsearch.ElasticsearchCommand("INSERT INTO Orders (ShipCity) VALUES (@myShipCity)", $conn)
$cmd.Parameters.Add(new System.Data.CData.Elasticsearch.ElasticsearchParameter("@myShipCity","New York"))
$cmd.ExecuteNonQuery()
````
### DELETE
```PowerShell
Remove-Elasticsearch -Connection $Elasticsearch -Table "Orders" -Id "MyId"

$cmd = New-Object System.Data.CData.Elasticsearch.ElasticsearchCommand("DELETE FROM Orders WHERE Id=@myId", $conn)
$cmd.Parameters.Add(new System.Data.CData.Elasticsearch.ElasticsearchParameter("@myId","001d000000YBRseAAH"))
$cmd.ExecuteNonQuery()
````
# ODBC

`Get-Command -Module Wdac` \
`Get-OdbcDriver | ft` список встановлених драйверів

https://www.elastic.co/guide/en/elasticsearch/reference/current/sql-client-apps-ps1.html
```PowerShell
$connectstring = "DSN=Local Elasticsearch;"
$sql = "SELECT * FROM library"
$conn = New-Object System.Data.Odbc.OdbcConnection($connectstring)
$conn.open()
$cmd = New-Object system.Data.Odbc.OdbcCommand($sql,$conn)
$da = New-Object system.Data.Odbc.OdbcDataAdapter($cmd)
$dt = New-Object system.Data.datatable
$null = $da.fill($dt)
$conn.close()
$dt
````
# PostgreSQL

Завантажити та встановити драйвер: https://www.postgresql.org/ftp/odbc/versions/msi/
```PowerShell
$dbServer = "192.168.3.101"
$port = "5432"
$dbName = "test"
$dbUser = "admin"
$dbPass = "admin"
$szConnect = "Driver={PostgreSQL Unicode(x64)};Server=$dbServer;Port=$port;Database=$dbName;Uid=$dbUser;Pwd=$dbPass;"

$cnDB = New-Object System.Data.Odbc.OdbcConnection($szConnect)
$dsDB = New-Object System.Data.DataSet
try {
$cnDB.Open()
$adDB = New-Object System.Data.Odbc.OdbcDataAdapter
$adDB.SelectCommand = New-Object System.Data.Odbc.OdbcCommand("SELECT id, name, age, login FROM public.users" , $cnDB)
$adDB.Fill($dsDB)
$cnDB.Close()
}
catch [System.Data.Odbc.OdbcException] {
$_.Exception
$_.Exception.Message
$_.Exception.ItemName
}
foreach ($row in $dsDB[0].Tables[0].Rows) {
$row.login
$row.age
}
````
# WMI

### WMI/CIM (Windows Management Instrumentation/Common Information Model)	
`Get-WmiObjec -ComputerName localhost -Namespace root -class "__NAMESPACE" | select name,__namespace` відобразити дочірні Namespace (логічні ієрархічні групи) \
`Get-WmiObject -List` відобразити всі класи простору імен "root\cimv2" (за умовчанням), властивості (описують конфігурацію та поточний стан керованого ресурсу) та їх методи (які дії дозволяє виконати над цим ресурсом) \
`Get-WmiObject-List | Where-Object {$_.name -match "video"}` пошук класу на ім'я, його властивості та методи \
`Get-WmiObject -ComputerName localhost -Class Win32_VideoController` відобразити вміст властивостей класу

`gwmi-List | where name -match "service" | ft -auto` якщо в таблиці присутні Methods, то можна взаємодіяти {StartService, StopService} \
`gwmi-Class win32_service | select *` відобразити список усіх служб та всіх їх властивостей \
`Get-CimInstance Win32_service` звертається на пряму до "root\cimv2"
`gwmi win32_service -Filter "name='Zabbix Agent'"` відфільтрувати висновок на ім'я \
`(gwmi win32_service -Filter "name='Zabbix Agent'").State` відобразити конкретну властивість \
`gwmi win32_service -Filter "State = 'Running'"` відфільтрувати запущені служби \
`gwmi win32_service -Filter "StartMode = 'Auto'"` відфільтрувати служби за методом запуску \
`gwmi -Query 'select * from win32_service where startmode="Auto"'` WQL-запит (WMI Query Language) \
`gwmi win32_service | Get-Member -MemberType Method` відобразити всі методи взаємодії з описом застосування (Delete, StartService) \
`(gwmi win32_service -Filter 'name="Zabbix Agent"').Delete()` видалити службу \
`(gwmi win32_service -Filter 'name="MSSQL$MSSQLE"').StartService()` запустити службу

`Get-CimInstance -ComputerName $srv Win32_OperatingSystem | select LastBootUpTime` час останнього включення \
`gwmi -ComputerName $srv -Class Win32_OperatingSystem | select LocalDateTime,LastBootUpTime` поточний час та час останнього включення \
`gwmi Win32_OperatingSystem | Get-Member -MemberType Method` методи reboot та shutdown \
`(gwmi Win32_OperatingSystem -EnableAllPrivileges).Reboot()` використовується з ключем підвищення привілеїв \
`(gwmi Win32_OperatingSystem -EnableAllPrivileges).Win32Shutdown(0)` завершення сеансу користувача
```PowerShell
$system = Get-WmiObject -Class Win32_OperatingSystem
$InstallDate = [Management.ManagementDateTimeconverter]::ToDateTime($system.installdate)` Отримуємо дату встановлення ОС
$AfterInstallDays = ((Get-Date) — $Installdate).Days` Обчислюємо час, що минув з моменту встановлення
$ShortInstallDate = "{0:yyyy-MM-dd HH:MM}" -f ($InstallDate)
"Встановлено систему: $ShortInstallDate (Пройшло $AfterInstalldays днів)"
````
`(Get-WmiObject win32_battery).estimatedChargeRemaining` заряд батареї у відсотках \
`gwmi Win32_UserAccount` доменні користувачі \
`(gwmi Win32_SystemUsers).PartComponent` \
`Get-CimInstance -ClassName Win32_LogonSession` \
`Get-CimInstance -ClassName Win32_BIOS`

`gwmi -list -Namespace root\CIMV2\Terminalservices` \
`(gwmi -Class Win32_TerminalServiceSetting -Namespace root\CIMV2\TerminalServices).AllowTSConnections` \
`(gwmi -Class Win32_TerminalServiceSetting -Namespace root\CIMV2\TerminalServices).SetAllowTSConnections(1)` включити RDP
````
$srv = "localhost"
gwmi Win32_logicalDisk -ComputerName $srv | where {$_.Size -ne $null} | select @{
Label="Value"; Expression={$_.DeviceID}}, @{Label="AllSize"; Expression={
[string]([int]($_.Size/1Gb))+"GB"}},@{Label="FreeSize"; Expression={
[string]([int]($_.FreeSpace/1Gb))+"GB"}}, @{Label="Free%"; Expression={
[string]([int]($_.FreeSpace/$_.Size*100))+" %"}}
````
### NLA (Network Level Authentication)
`(gwmi -class "Win32_TSGeneralSetting" -Namespace root\cimv2\Terminalservices -Filter "TerminalName='RDP-tcp'").UserAuthenticationRequired` \
`(gwmi -class "Win32_TSGeneralSetting" -Namespace root\cimv2\Terminalservices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(1)` включити NLA \
`Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name SecurityLayer` відобразити значення (2) \
`Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication` відобразити значення (1) \
`Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name SecurityLayer -Value 0` змінити значення \
`Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -Value 0` \
`REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters /v AllowEncryptionOracle /t REG_DWORD /d 2` відключити на клієнтському комп'ютері перевірку версії CredSSP, якщо на цільовому комп'ютері15 2018 року

# Regedit

`Get-PSDrive` список всіх доступних дисків/розділів, їх розмір та гілок реєстру \
`cd HKLM:\` HKEY_LOCAL_MACHINE \
`cd HKCU:\` HKEY_CURRENT_USER \
`Get-Item` отримати інформацію про гілку реєстру \
`New-Item` створити новий розділ реєстру \
`Remove-Item` видалити гілку реєстру \
`Get-ItemProperty` отримати значення ключів/параметрів реєстру (це властивості гілки реєстру, аналогічно властивостям файлу) \
`Set-ItemProperty` змінити назву або значення параметра реєстру \
`New-ItemProperty` створити параметр реєстру \
`Remove-ItemProperty` видалити параметр

`Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName` список встановлених програм \
`Get-Item HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676\00000002` переглянути вміст Items \
`(Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676\00000002).
`$reg_path = "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676\00000002"` \
`$sig_name = "auto"` \
`Set-ItemProperty -Path $reg_path -Name "New Signature" -Value $sig_name` змінити або додати в корені гілки (Path) властивість (Name) зі значенням (Value) \
`Set-ItemProperty -Path $reg_path -Name "Reply-Forward Signature" -Value $sig_name`
````
Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe]
"Debugger"="\"C:\Windows\System32\Taskmgr.exe\""
````
# Performance

`lodctr /R` перестворити лічильників продуктивності із системного сховища архівів (так само виправляє лічильники для CIM, наприклад, для cpu Win32_PerfFormattedData_PerfOS_Processor та iops Win32_PerfFormattedData_PerfDisk_PhysicalDisk) \
`(Get-Counter -ListSet *).CounterSetName` вивести список усіх доступних лічильників продуктивності в системі \
`(Get-Counter -ListSet *memory*).Counter` пошук по wildcard-імені у всіх лічильниках (включаючи дочірні) \
`Get-Counter "\Memory\Available MBytes"` обсяг вільної оперативної пам'яті \
`Get-Counter -cn $srv "\LogicalDisk(*)\% Free Space"` % вільного місця на всіх розділах дисків \
`(Get-Counter "\Process(*)\ID Process").CounterSamples` \
`Get-Counter "\Processor(_Total)\% Processor Time" -ComputerName $srv -MaxSamples 5 -SampleInterval 2` 5 перевірок кожні 2 секунди \
`Get-Counter "\Процесор(_Total)\% завантаженості процесора" -Continuous` безперервно \
`(Get-Counter "\Процесор(*)\% завантаженості процесора").CounterSamples`

`(Get-Counter -ListSet *інтерфейс*).Counter` знайти всі лічильники \
`Get-Counter "\Мережевий інтерфейс(*)\Всього байт/с"` відобразити всі адаптери (вибрати трафіку, що діє)
```PowerShell
$WARNING = 25
$CRITICAL = 50
$TransferRate = ((Get-Counter "\\huawei-mb-x-pro\мережевий інтерфейс(intel[r] wi-fi 6e ax211 160mhz)\всього байт/с"
). countersamples | select -ExpandProperty CookedValue)*8
$NetworkUtilisation = [math]::round($TransferRate/1000000000*100,2)
if ($NetworkUtilisation -gt $CRITICAL){
Write-Output "CRITICAL: $($NetworkUtilisation) % Network utilisation, $($TransferRate.ToString('N0')) b/s"
#exit 2		
}
if ($NetworkUtilisation -gt $WARNING){
Write-Output "WARNING: $($NetworkUtilisation) % Network utilisation, $($TransferRate.ToString('N0')) b/s"
#exit 1
}
Write-Output "OK: $($NetworkUtilisation) % Network utilisation, $($TransferRate.ToString('N0')) b/s"
#exit 0
````
# SNMP

### Setup SNMP Service

`Install-WindowsFeature SNMP-Service,SNMP-WMI-Provider -IncludeManagementTools` встановити роль SNMP і WMI провайдер через Server Manager \
`Get-WindowsFeature SNMP*` \
`Add-WindowsCapability -Online -Name SNMP.Client~~~~0.0.1.0` встановити компонент Feature On Demand для Windows 10/11` \
`Get-Service SNMP*` \
`Get-NetFirewallrule -DisplayName *snmp* | ft` \
`Get-NetFirewallrule -DisplayName *snmp* | Enable-NetFirewallRule`

### Setting SNMP Service via Regedit

Agent: \
`New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SNMP\Parameters\RFC1156Agent" -Name "sysContact" -Value "lifailon-user"' створити (New) або змінити (Set) \
`New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SNMP\Parameters\RFC1156Agent" -Name "sysLocation" -Value "plex-server"`

Security: \
`New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\services\SNMP\Parameters\TrapConfiguration\public"` створити новий community string \
`New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" -Name "public" -Value 16` призначити права на public \
`1 - NONE` \
`2 - NOTIFY` дозволяє отримувати SNMP пастки \
`4 - READ ONLY` дозволяє отримувати дані з пристрою \
`8 - READ WRITE` дозволяє отримувати дані та змінювати конфігурацію пристрою \
`16 — READ CREATE` дозволяє читати дані, змінювати та створювати об'єкти \
`New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers" -Name "1" -Value "192.168.3.99"` від кого дозволено приймати запити \
`Get-Service SNMP | Restart-Service`

### snmpwalk
`snmpwalk -v 2c -c public 192.168.3.100` \
`snmpwalk -v 2c -c public -O e 192.168.3.100`

### Modules

`Install-Module -Name SNMP` \
`Get-SnmpData -IP 192.168.3.100 -OID 1.3.6.1.2.1.1.4.0 -UDPport 161 -Community public` \
`(Get-SnmpData -IP 192.168.3.100 -OID 1.3.6.1.2.1.1.4.0).Data` \
`Invoke-SnmpWalk -IP 192.168.3.100 -OID 1.3.6.1.2.1.1` пройтися по дереву OID \
`Invoke-SnmpWalk -IP 192.168.3.100 -OID 1.3.6.1.2.1.25.6.3.1.2` список установленого ПЗ \
`Invoke-SnmpWalk -IP 192.168.3.100 -OID 1.3.6.1.2.1.25.2.3.1` список розділів та пам'яті (C: D: Virtual Memory та Physical Memory) \
`Set-SnmpData` зміна даних на віддаленому пристрої

`Install-Module -Name SNMPv3` \
`Invoke-SNMPv3Get` отримання даних по одному OID \
`Invoke-SNMPv3Set` зміна даних \
`Invoke-SNMPv3Walk` обхід по дереву OID \
`Invoke-SNMPv3Walk -UserName lifailon -Target 192.168.3.100 -AuthSecret password -PrivSecret password -OID 1.3.6.1.2.1.1 -AuthType MD5 -PrivType AES128`

### Lextm.SharpSnmpLib

https://api.nuget.org/v3-flatcontainer/lextm.sharpsnmplib/12.5.2/lextm.sharpsnmplib.12.5.2.nupkg \
`Add-Type -LiteralPath "$home\Desktop\lextm.sharpsnmplib-12.5.2\net471\SharpSnmpLib.dll"`
```PowerShell
$port = 161
$OID = "1.3.6.1.2.1.1.4.0"
$variableList = New-Object Collections.Generic.List[Lextm.SharpSnmpLib.Variable]
$variableList.Add([Lextm.SharpSnmpLib.Variable]::new([Lextm.SharpSnmpLib.ObjectIdentifier]::new($OID))))
$timeout = 3000
[Net.IPAddress]$ip = "192.168.3.100"
$endpoint = New-Object Net.IpEndPoint $ip, $port
$Community = "public"
[Lextm.SharpSnmpLib.VersionCode]$Version = "V2"

$message = [Lextm.SharpSnmpLib.Messaging.Messenger]::Get(
$Version,
$endpoint,
$Community,
$variableList,
$TimeOut
)
$message.Data.ToString()
````
### Walk
```PowerShell
[Lextm.SharpSnmpLib.ObjectIdentifier]$OID = "1.3.6.1.2.1.1" # дерево або кінцевий OID
$WalkMode = [Lextm.SharpSnmpLib.Messaging.WalkMode]::WithinSubtree # режим обходу по дереву
$results = New-Object Collections.Generic.List[Lextm.SharpSnmpLib.Variable]
$message = [Lextm.SharpSnmpLib.Messaging.Messenger]::Walk(
$Version,
$endpoint,
$Community,
$OID,
$results,
$TimeOut,
$WalkMode
)
$results

$results2 = @()
foreach ($d in $results) {
$results2 +=[PSCustomObject]@{'ID'=$d.id.ToString();'Data'=$d.Data.ToString()} # перекодувати висновок рядково в рядок
}
$results2
````
# Zabbix

### Zabbix Agent Deploy
```PowerShell
$url = "https://cdn.zabbix.com/zabbix/binaries/stable/6.4/6.4.5/zabbix_agent2-6.4.5-windows-amd64-static.zip"
$path = "$home\Downloads\zabbix-agent2-6.4.5.zip"
$WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile($url, $path)` скачати файл
Expand-Archive $path -DestinationPath "C:\zabbix-agent2-6.4.5\"` розархівувати
Remove-Item $path` видалити архів
New-NetFirewallRule -DisplayName "Zabbix-Agent" -Profile Any -Direction Inbound -Action Allow -Protocol TCP -LocalPort 10050,10051` відкрити порти в FW

$ Zabbix_Server = "192.168.3.102"
$conf = "C:\zabbix-agent2-6.4.5\conf\zabbix_agent2.conf"
$cat = cat $conf
$rep = $cat -replace "Server=.+","Server=$Zabbix_Server"
$rep | Select-String Server=
$rep > $conf

$exe = "C:\zabbix-agent2-6.4.5\bin\zabbix_agent2.exe"
.$exe --config $conf --install` встановити службу
Get-Service * Zabbix * Agent * | Start-Service` запустити службу
#.$exe --config $conf --uninstall` видалити службу
````
### zabbix_sender

Створити host - задати довільне ім'я (powershell-host) та додати до групи \
Створити Items: \
Name: Service Count \
Type: Zabbix trapper \
Key: service.count \
Тип інформації: Numeric
```PowerShell
$path = "C:\zabbix-agent2-6.4.5\bin"
$scount = (Get-Service).Count
.$path\zabbix_sender.exe -z 192.168.3.102 -s "powershell-host" -k service.count -o $scount
````
### zabbix_get

`apt install zabbix-get` \
`nano /etc/zabbix/zabbix_agentd.conf` \
`Server=127.0.0.1,192.168.3.102,192.168.3.99` додати сервера для отримання даних zabbix_get з агента (як їх запитує сервер)

`.$path\zabbix_get -s 192.168.3.101 -p 10050 -k agent.version` перевірити версію агента \
`.$path\zabbix_get -s 192.168.3.101 -p 10050 -k agent.ping` 1 - ok \
`.$path\zabbix_get -s 192.168.3.101 -p 10050 -k net.if.discovery` список мережевих інтерфейсів \
`.$path\zabbix_get -s 192.168.3.101 -p 10050 -k net.if.in["ens33"]` \
`.$path\zabbix_get -s 192.168.3.101 -p 10050 -k net.if.out["ens33"]`

### UserParameter

`UserParameter=process.count,powershell -Command "(Get-Process).Count"` \
`UserParameter=process.vm[*],powershell -Command "(Get-Process $1).ws"`

Test: \
`C:\zabbix-agent2-6.4.5\bin\zabbix_get.exe -s 127.0.0.1 -p 10050 -k process.count` \
`C:\zabbix-agent2-6.4.5\bin\zabbix_get.exe -s 127.0.0.1 -p 10050 -k process.vm[zabbix_agent2] `\
`C:\zabbix-agent2-6.4.5\bin\zabbix_get.exe -s 127.0.0.1 -p 10050 -k process.vm[powershell]`

Створити нові Items: \
key: `process.count` \
key: `process.vm[zabbix_agent2]`

### Include

- Додати параметр Include для включення конфігураційних файлів плагінів, що підключаються
`'Include=.\zabbix_agent2.d\plugins.d\*.conf' >> C:\zabbix-agent2-6.4.5\conf\zabbix_agent2.conf`

- Створити конфігураційний файл з параметрами користувача в каталозі, шлях до якого вказаний в zabbix_agentd.conf \
`'UserParameter=Get-Query-Param[*],powershell.exe -noprofile -executionpolicy bypass -File C:\zabbix-agent2-6.4.5\conf\zabbix_agent2.d\scripts\User-Sessions\Get-Query- Param.ps1 $1' > C:\zabbix-agent2-6.4.5\conf\zabbix_agent2.d\plugins.d\User-Sessions.conf`

- Помістити скрипт Get-Query-Param.ps1 у каталог, шлях до якого вказано в User-Sessions.conf. Скрипт містить параметри користувача, які він приймає від Zabbix сервера для передачі їх у функції скрипта.
```PowerShell
Param([string]$select)
if ($select -eq "ACTIVEUSER") {
(Get-Query | where status -match "Active").User
}
if ($select -eq "INACTIVEUSER") {
(Get-Query | where status -match "Disconnect").User
}
if ($select -eq "ACTIVECOUNT") {
(Get-Query | where status -match "Active").
}
if ($select -eq "INACTIVECOUNT") {
(Get-Query | де status-match "Disconnect").
}
````
- Перевірити роботу скрипту:

`$path = "C:\zabbix-agent2-6.4.5\conf\zabbix_agent2.d\scripts\User-Sessions"` \
`.$path\Get-Query-Param.ps1 ACTIVEUSER` \
`.$path\Get-Query-Param.ps1 INACTIVEUSER` \
`.$path\Get-Query-Param.ps1 ACTIVECOUNT` \
`.$path\Get-Query-Param.ps1 INACTIVECOUNT`

- Створити Items з ключами:

`Get-Query-Param[ACTIVEUSER]` Type: Text \
`Get-Query-Param[INACTIVEUSER]` Type: Text \
`Get-Query-Param[ACTIVECOUNT]` Type: Int \
`Get-Query-Param[INACTIVECOUNT]` Type: Int

- Макроси:

`{$ACTIVEMAX} = 16` \
`{$ACTIVEMIN} = 0`

- Тригери:

`last(/Windows-User-Sessions/Get-Query-Param[ACTIVECOUNT])>{$ACTIVEMAX}` \
`min(/Windows-User-Sessions/Get-Query-Param[ACTIVECOUNT],24h)={$ACTIVEMIN}`

### zabbix_agent2.conf
````
# Агент може працювати в пасивному (сервер забирає саму інформацію) та активному режимі (агент сам відправляє):
Server=192.168.3.102
ServerActive=192.168.3.102
# Потрібно вказати hostname для ServerActive:
Hostname=huawei-book-01
# Якщо не вказано, використовується для генерації імені хоста (ігнорується, якщо ім'я хоста визначено):
# HostnameItem=system.hostname
# Як часто оновлюється список активних перевірок, у секундах (Range: 60-3600):
RefreshActiveChecks=120
# IP-адреса джерела для вихідних з'єднань:
# SourceIP =
# Агент буде слухати на цьому порту з'єднання з сервером (Range: 1024-32767):
# ListenPort=10050
# Список IP-адрес, які агент повинен прослуховувати через кому
# ListenIP=0.0.0.0
# Агент буде прослуховувати цей порт для запитів статусу HTTP (Range: 1024-32767):
# StatusPort =
ControlSocket=\\.\pipe\agent.sock
# Куди вести журнал (file/syslog/console):
LogType=file
LogFile=C:\zabbix-agent2-6.4.5\zabbix_agent2.log
# Розмір лога від 0-1024 MB (0 - вимкнути автоматичну ротацію логів)
LogFileSize=100
# Рівень логування. 4 - для налагодження (видає багато інформації)
DebugLevel=4
````
### API Token

https://www.zabbix.com/documentation/current/en/manual/api/reference

`$ip = "192.168.3.102"` \
`$url = "http://$ip/zabbix/api_jsonrpc.php"`
```PowerShell
$ data = @ {
"jsonrpc" = "2.0";
"method"="user.login";
"params" = @ {
"username"="Admin";` у версії до 6.4 параметр "user"
"password" = "zabbix";
};
"id"=1;
}
$token = (Invoke-RestMethod -Method POST -Uri $url -Body ($data | ConvertTo-Json) -ContentType "application/json").Result
````
`$token = "2eefd25fdf1590ebcdb7978b5bcea1fff755c65b255da8cbd723181b639bb789"` згенерувати токен в UI (http://192.168.3.102/zabbix/abb=

### user.get
```PowerShell
$ data = @ {
"jsonrpc" = "2.0";
"method"="user.get";
"params" = @ {
};
"auth"=$token;
"id"=1;
}
$users = (Invoke-RestMethod -Method POST -Uri $url -Body ($data | ConvertTo-Json) -ContentType "application/json").Result
````
### problem.get
```PowerShell
$ data = @ {
"jsonrpc" = "2.0";
"method"="problem.get";
"params" = @ {
};
"auth"=$token;
"id"=1;
}
(Invoke-RestMethod -Method POST -Uri $url -Body ($data | ConvertTo-Json) -ContentType "application/json").Result
````
### host.get

Отримати список усіх хостів (ім'я та id)

https://www.zabbix.com/documentation/current/en/manual/api/reference/host

host.create - creating new hosts \
host.delete - deleting hosts \
host.get - retrieving hosts \
host.massadd - adding related objects to hosts \
host.massremove - remove related objects from hosts \
host.massupdate - replacing or removing related objects from hosts \
host.update - updating hosts
```PowerShell
$ data = @ {
"jsonrpc" = "2.0";
"method"="host.get";
"params" = @ {
"output"=@(` відфільтрувати висновок
"hostid";
"host";
);
};
"id"=2;
"auth"=$token;
}
$hosts = (Invoke-RestMethod -Method POST -Uri $url -Body ($data | ConvertTo-Json) -ContentType "application/json").Result
$host_id = $hosts[3].hostid` забрати id хоста за індексом
````
### item.get

Отримати id елементів даних за найменуванням ключа для конкретного хоста
```PowerShell
$ data = @ {
"jsonrpc" = "2.0";
"method"="item.get";
"params" = @ {
"hostids"=@($host_id);` відфільтрувати по хосту
};
"auth"=$token;
"id"=1;
}
$items = (Invoke-RestMethod -Method POST -Uri $url -Body ($data | ConvertTo-Json) -ContentType "application/json").Result
$items_id = ($items | where key_ -match system.uptime).itemid` забрати id елемента даних
````
### history.get

Отримати всю історію елемента даних з його id
```PowerShell
$ data = @ {
"jsonrpc" = "2.0";
"method"="history.get";
"params" = @ {
"hostids" = @ ($ host_id); фільтрація по хосту
"itemids"=@($items_id);` фільтрація за елементом даних
};
"auth"=$token;
"id"=1;
}
$items_data_uptime = (Invoke-RestMethod -Method POST -Uri $url -Body ($data | ConvertTo-Json) -ContentType "application/json").Result` отримати всі дані по ключу у конкретного хоста
````
### Convert Secconds To TimeSpan and DateTime

`$sec = $items_data_uptime.value`
```PowerShell
function ConvertSecondsTo-TimeSpan {
param (
$insec
)
$TimeSpan = [TimeSpan]::fromseconds($insec)
"{0:dd' day 'hh\:mm\:ss}" -f $TimeSpan
}
````
`$UpTime = ConvertSecondsTo-TimeSpan $sec[-1]`

### Convert From Unix Time

`$time = $items_data_uptime.clock`
```PowerShell
function ConvertFrom-UnixTime {
param (
$intime
)
$EpochTime = [DateTime]"1/1/1970"
$TimeZone = Get-TimeZone
$UTCTime = $EpochTime.AddSeconds($intime)
$UTCTime.AddMinutes($TimeZone.BaseUtcOffset.TotalMinutes)
}
````
`$GetDataTime = ConvertFrom-UnixTime $time[-1]`

`($hosts | where hostid -eq $host_id).host` отримати ім'я хоста \
`$UpTime` останнє отримане значення часу роботи хоста \
`$GetDataTime` час останнього отриманого значення

# pki

`New-SelfSignedCertificate -CertStoreLocation Cert:\LocalMachine\My -DnsName "$env:computername" -FriendlyName "Test Certificate" -NotAfter (Get-Date).AddYears(5)` створити самопідписаний сертифікат (в LocalMach \Особисте) з терміном дії 5 років

`Get-ChildItem -Path Cert:\CurrentUser\Root\` список усіх встановлених сертифікатів у сховищі Довірені кореневі ЦС Поточного користувача \
`Get-ChildItem -Path Cert:\CurrentUser\My\` список сертифікатів, що самозавіряють, в Особисте сховище Поточного користувача \
`Get-ChildItem -Path Cert:\LocalMachine\My\` список сертифікатів, що самозавіряють, в Особисте сховище Локального комп'ютера \
`Get-ChildItem -Path Cert:\LocalMachine\My\ | select NotBefore,NotAfter,Thumbprint,Subject` термін дії сертифіката \
`Get-ChildItem -Path Cert:\LocalMachine\My\ | where Thumbprint -eq D9356FB774EE0E6206B7D5B59B99102CA5B17BDA` пошук сертифікат за відбитком

`Get-ChildItem -Path $env:APPDATA\Microsoft\SystemCertificates\My\Certificates\` сертифікати у файловій системі, кожен файл відповідає сертифікату, встановленому в особистому сховищі поточного користувача \
`Get-ChildItem -Path $env:APPDATA\Microsoft\SystemCertificates\My\Keys\` посилання на об'єкти закритих ключів, створених постачальником сховища ключів (KSP) \
`Get-ChildItem -Path HKCU:\Software\Microsoft\SystemCertificates\CA\Certificates | ft -AutoSize` список сертифікатів у реєстрі користувача, що увійшов до системи

`$cert = (Get-ChildItem -Path Cert:\CurrentUser\My\)[1]` вибрати сертифікат \
`$cert | Remove-Item` видалити сертифікат

`Export-Certificate -FilePath $home\Desktop\certificate.cer -Cert $cert` експортувати сертифікат \
`$cert.HasPrivateKey` перевірити наявність закритого ключа \
$pass = "password" | ConvertTo-SecureString -AsPlainText -Force` створити пароль для шифрування закритого ключа \
`Export-PfxCertificate -FilePath $home\Desktop\certificate.pfx -Password $pass -Cert $certificate` експортувати сертифікат із закритим ключем

`Import-Certificate -FilePath $home\Desktop\certificate.cer -CertStoreLocation Cert:\CurrentUser\My` імпортувати сертифікат \
`Import-PfxCertificate -Exportable -Password $pass -CertStoreLocation Cert:\CurrentUser\My -FilePath $home\Desktop\certificate.pfx`

# OpenSSL
```PowerShell
Invoke-WebRequest -Uri https://slproweb.com/download/Win64OpenSSL_Light-3_1_1.msi -OutFile $home\Downloads\OpenSSL-Light-3.1.1.msi
Start-Process $home\Downloads\OpenSSL-Light-3.1.1.msi -ArgumentList '/quiet' -Wait` встановити msi пакет у тихому режимі (запуск від імені Адміністратора)
rm $home\Downloads\OpenSSL-Light-3.1.1.msi
cd "C:\Program Files\OpenSSL-Win64\bin"
````
- Змінити пароль для PFX \
`openssl pkcs12 -in "C:\Cert\domain.ru.pfx" -out "C:\Cert\domain.ru.pem" -nodes` експортуємо наявний сертифікат та закритий ключ до .pem-файлу без пароля із зазначенням поточного пароля \
`openssl pkcs12 -export -in "C:\Cert\domain.ru.pem" -out "C:\Cert\domain.ru_password.pfx" -nodes` конвертуємо .pem назад у .pfx з вказівкою нового пароля

- Конвертація із закритого та відкритого ключа PEM у PFX \
`openssl pkcs12 -export -in "C:\tmp\vpn\vpn.itproblog.ru-crt.pem" -inkey "C:\tmp\vpn\vpn.itproblog.ru-key.pem" -out "C: \tmp\vpn\vpn.iiproblog.ru.pfx"` \
in – шлях до файлу з відкритим ключем \
inkey – шлях до файлу із закритим ключом \
out - шлях до файлу, в який буде конвертовано сертифікат (pfx)

- Конвертація PFX в CRT \
`openssl pkcs12 -in "C:\OpenSSL-Win64\bin\_.domain.ru.pfx" -clcerts -out "C:\OpenSSL-Win64\bin\_.domain.ru.crt"` вказується поточний і 2 рази новий пароль PEM pass phrase (файл містить EGIN CERTIFICATE та BEGIN ENCRYPTED PRIVATE KEY) \
`openssl pkcs12 -in "C:\OpenSSL-Win64\bin\_.domain.ru.pfx" -clcerts -nokeys -out "C:\OpenSSL-Win64\bin\_.domain.ru.crt"` без ключа отримати відкриту частину (файл містить тільки EGIN CERTIFICATE)

- Конвертація PFX в KEY \
`openssl pkcs12 -in "C:\OpenSSL-Win64\bin\_.domain.ru.pfx" -nocerts -out "C:\OpenSSL-Win64\bin\_.domain.ru.key"` файл містить тільки BEGIN ENCRYPTED PRIVATE KEY

- Зняти пароль до закритого ключа.
`openssl rsa -in "C:\OpenSSL-Win64\bin\_.domain.ru.key" -out "C:\OpenSSL-Win64\bin\_.domain.ru-decrypted.key"`

- CRT та KEY у PFX: \
`openssl pkcs12 -inkey certificate.key -in certificate.crt -export -out certificate.pfx`

# OpenVPN

`Invoke-WebRequest -Uri https://swupdate.openvpn.org/community/releases/OpenVPN-2.6.5-I001-amd64.msi -OutFile $home\Downloads\OpenVPN-2.6.5.msi` \
`Start-Process $home\Downloads\OpenVPN-2.6.5.msi -ArgumentList '/quiet /SELECT_OPENSSL_UTILITIES=1' -Wait` \
`msiexec /i $home\Downloads\OpenVPN-2.6.5.msi ADDLOCAL=EasyRSA /passive /quiet # встановити окремий компонент EasyRSA Certificate Management Scripts` \
`# msiexec /i $home\Downloads\OpenVPN-2.6.5.msi ADDLOCAL=OpenVPN.Service,Drivers,Drivers.Wintun,OpenVPN,OpenVPN.GUI,OpenVPN.GUI.OnLogon,EasyRSA /passive` вибіркова установка \
`# Invoke-WebRequest -Uri https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.5/EasyRSA-3.1.5-win64.zip -OutFile $home\Downloads\EasyRSA-3.1.5 .zip` скачати окремий пакет EasyRSA \
`rm $home\Downloads\OpenVPN-2.6.5.msi`

`cd "C:\Program Files\OpenVPN\easy-rsa"` \
`Copy-Item vars.example vars` файл конфігурації для EasyRSA
````
set_var EASYRSA_TEMP_DIR "$EASYRSA_PKI"
set_var EASYRSA_REQ_COUNTRY "UA"
set_var EASYRSA_REQ_PROVINCE "MSK"
set_var EASYRSA_REQ_CITY "MSK"
set_var EASYRSA_REQ_ORG "FAILON.NET"
set_var EASYRSA_REQ_EMAIL "lifailon@domain.ru"
set_var EASYRSA_REQ_OU "IT"
#set_var EASYRSA_KEY_SIZE 2048
#set_var EASYRSA_CA_EXPIRE 3650
#set_var EASYRSA_CERT_EXPIRE 825
````
`.\EasyRSA-Start.bat` середа EasyRSA Shell \
`easyrsa init-pki` ініціалізація PKI, створює директорію: C:\Program Files\OpenVPN\easy-rsa\pki та читає змінні файлу \easy-rsa\vars \
`easyrsa build-ca` генерація кореневого CA із зазначенням пароля та довільне ім'я сервера (\pki\ca.crt та \pki\private\ca.key) \
`easyrsa gen-req server nopass` генерація запиту сертифіката та ключ для сервера OpenVPN - yes (\pki\reqs\server.req та \pki\private\server.key) \
`easyrsa sign-req server server` підписати запит на випуск сертифіката сервера за допомогою CA - yes (\pki\issued\server.crt) \
`easyrsa gen-dh` створити ключ Діффі-Хеллмана (\pki\dh.pem) \
`easyrsa gen-req client1` nopass` генерація запиту сертифіката та ключ для клієнта OpenVPN (\pki\reqs\client1.req та \pki\private\client1.key)` \
`easyrsa sign-req client client1` підписати запит на випуск сертифіката клієнта за допомогою CA - yes (\pki\issued\client1.crt) \
`easyrsa revoke client1` відкликати сертифікат користувача \
`openssl rsa -in "C:\Program Files\OpenVPN\easy-rsa\pki\private\client1.key" -out "C:\Program Files\OpenVPN\easy-rsa\pki\private\client1_nopass.key"` зняти захист паролем для ключа (BEGIN ENCRYPTED PRIVATE KEY -> BEGIN PRIVATE KEY) \
`exit` \
`cd "C:\Program Files\OpenVPN\bin"` \
`.\openvpn --genkey secret ta.key` генерація ключа tls-auth (\bin\ta.key) \
`Move-Item "C:\Program Files\OpenVPN\bin\ta.key" "C:\Program Files\OpenVPN\easy-rsa\pki\"`

### server.ovpn

`# Copy-Item "C:\Program Files\OpenVPN\sample-config\server.ovpn" "C:\Program Files\OpenVPN\config-auto\server.ovpn"` \
`New-Item -ItemType File -Path "C:\Program Files\OpenVPN\config-auto\server.ovpn"`
````
port 1194
proto udp
Що саме інкапсулювати в тунелі (ethernet фрейми - tap або ip пакети - tun)
dev tun
ca "C:\Program Files\OpenVPN\easy-rsa\pki\ca.crt"
cert "C:\Program Files\OpenVPN\easy-rsa\pki\issued\server.crt"
key "C:\Program Files\OpenVPN\easy-rsa\pki\private\server.key"
dh "C:\Program Files\OpenVPN\easy-rsa\pki\dh.pem"
server 192.168.4.0 255.255.255.0
# Зберігає список зіставлення IP для клієнтів, щоб призначити ту ж адресу при перезапуску сервера
# ifconfig-pool-persist "C:\Program Files\OpenVPN\dhcp-client-list.txt"
# Дозволити клієнтам підключатися під одним ключем
# duplicate-cn
# max-clients 30
# Дозволити обмін трафіком між клієнтами
client-to-client
# compress
tls-auth "C:\Program Files\OpenVPN\easy-rsa\pki\ta.key" 0
cipher AES-256-GCM
keepalive 20 60
# Не перечитувати файли ключів під час перезапуску тунелю
persist-key
# Залишає без зміни пристрою tun/tap під час перезапуску OpenVPN
persist-tun
status "C:\Program Files\OpenVPN\log\status.log"
log "C:\Program Files\OpenVPN\log\openvpn.log"
verb 3
mute 20
windows-driver wintun
# Відкрити доступ до підмережі за сервером
push "route 192.168.3.0 255.255.255.0"
push "route 192.168.4.0 255.255.255.0"
# Загорнути всі запити клієнта (у тому числі Інтернет трафік) на сервер OpenVPN
# push "redirect-gateway def1"
# push "dhcp-option DNS 192.168.3.101"
# push "dhcp-option DOMAIN failon.net"
````
`New-NetFirewallRule -DisplayName "AllowOpenVPN-In" -Direction Inbound -Protocol UDP -LocalPort 1194 -Action Allow` на сервері \
`New-NetFirewallRule -DisplayName "AllowOpenVPN-Out" -Direction Outbound -Protocol UDP –LocalPort 1194 -Action Allow` на клієнті \
`Get-Service *openvpn* | Restart-Service`

### client.ovpn

`# Copy-Item "C:\Program Files\OpenVPN\sample-config\client.ovpn" "C:\Program Files\OpenVPN\config-auto\client.ovpn"` \
`New-Item -ItemType File -Path "C:\Program Files\OpenVPN\config-auto\client.ovpn"`
````
client
dev tun
proto udp
remote 26.115.154.67 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert client1.crt
key client1.key
remote-cert-tls server
tls-auth ta.key 1
cipher AES-256-GCM
connect-retry-max 25
# Використовувати драйвер wintun та повний шлях до сертифікатів при використанні openvpn gui
windows-driver wintun
verb 3
````
### Client

`iwr -Uri https://openvpn.net/downloads/openvpn-connect-v3-windows.msi -OutFile "$home\downloads\OpenVPN-Connect-3.msi"` \
Передати конфігурацію та ключі: \
`client.ovpn` \
`ca.crt` \
`dh.pem` \
`ta.key` \
`client1.crt` \
`client1.key`

# Route

`Get-Service RemoteAccess | Stop-Service`\
`Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IPEnableRouter" -Value 1` включає IP маршрутизацію \
`(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters").IPEnableRouter` \
`Get-NetIPInterface | select ifIndex,InterfaceAlias,AddressFamily,ConnectionState,Forwarding | ft` відобразити мережеві інтерфейси \
`Set-NetIPInterface -ifIndex 13 -Forwarding Enabled` увімкнути переадресацію на інтерфейсі

`sysctl net.ipv4.ip_forward=1` \
`echo "sysctl net.ipv4.ip_forward = 1" >> /etc/sysctl.conf`

`Get-NetRoute` \
`New-NetRoute -DestinationPrefix "192.168.3.0/24" -NextHop "192.168.4.1" -InterfaceIndex 8` \
`route -p add 192.168.3.0 mask 255.255.255.0 192.168.4.1 metric 1` \
`route -p change 192.168.3.0 mask 255.255.255.0 192.168.4.1 metric 2` \
`route -p add 192.168.3.0 mask 255.255.255.0 192.168.4.1 metric 1 if 7` вказати номер мережного інтерфейсу на який необхідно надсилати пакет (Wintun Userspace Tunnel) \
`route print -4` \
`route delete 192.168.3.0`

`tracert 192.168.3.101` з 192.168.4.6
````
1 17 ms * 22 ms 192.168.4.1
2 12 ms 13 ms 14 ms 192.168.3.101
````
`route add-net 192.168.4.0 netmask 255.255.255.0 gw 192.168.3.100` \
`route -e`

`traceroute 192.168.4.6` з 192.168.3.101
````
1 192.168.3.100 (192.168.3.100) 0.148 ms 0.110 ms 0.106 ms
2 192.168.4.6 (192.168.4.6) 14.573 ms * *
````
`ping 192.168.3.101 -t` з 192.168.4.6\
`tcpdump -n -i ens33 icmp` на 192.168.3.101
````
14:36:34.533771 IP 192.168.4.6 > 192.168.3.101: ICMP echo request, id 1, seq 2962, length 40 # надіслав запит
14:36:34.533806 IP 192.168.3.101 > 192.168.4.6: ICMP echo reply, id 1, seq 2962, length 40 # надіслав відповідь
````
# NAT

`Get-Command -Module NetNat` \
`New-NetNat -Name LocalNat -InternalIPInterfaceAddressPrefix "192.168.3.0/24"` \
`Add-NetNatStaticMapping -NatName LocalNat -Protocol TCP -ExternalIPAddress 0.0.0.0 -ExternalPort 80 -InternalIPAddress 192.168.3.102 -InternalPort 80` \
`Remove-NetNatStaticMapping -StaticMappingID 0` \
`Remove-NetNat -Name LocalNat`

# WireGuard

`Invoke-WebRequest "https://download.wireguard.com/windows-client/wireguard-amd64-0.5.3.msi" -OutFile "$home\Downloads\WireGuard-Client-0.5.3.msi"` \
`msiexec.exe /i "$home\Downloads\WireGuard-Client-0.5.3.msi" DO_NOT_LAUNCH=1 /qn` \
`Invoke-WebRequest "http://www.wiresock.net/downloads/wiresock-vpn-gateway-x64-1.1.4.1.msi" -OutFile "$home\Downloads\WireSock-VPN-Gateway-1.1.4.1.msi "`\
`msiexec.exe /i "http://www.wiresock.net/downloads/wiresock-vpn-gateway-x64-1.1.4.1.msi" /qn` \
`$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")` \
`wg-quick-config -add -start` \
`26.115.154.67:8181` \
`192.168.21.4/24` \
`Successfully saved client configuration: C:\ProgramData\NT KERNEL\WireSock VPN Gateway\wsclient_1.conf` \
`Successfully saved server configuration: C:\ProgramData\NT KERNEL\WireSock VPN Gateway\wiresock.conf` \
`get-service *wire*` \
`wg show` \
`wg-quick-config -add -restart` add client

wiresock.conf
````
[Interface]
PrivateKey = gCHC0g2JPwr6sXPiaOL4/KTkMyjN9TculrJUA/GORV8=
Address = 192.168.21.5/24
ListenPort = 8181

[Peer]
PublicKey = NoSxjew2RCHiUzI6mlahjd4I+0EcLsoYom/H01z91yU=
AllowedIPs = 192.168.21.6/32
````
wsclient_1.conf (додати маршрути для клієнта в AllowedIPs)
````
[Interface]
PrivateKey = yIpRQRmaGrrk9Y+49E8JhEpFmKzSeecvUAdeNgf1hUM=
Address = 192.168.21.6/24
DNS = 8.8.8.8, 1.1.1.1
MTU = 1420

[Peer]
PublicKey = Fp7674VSYeGj8CYt6RCKR7Qz1y/IKUXCw8ImOFhX3hk=
AllowedIPs = 192.168.21.0/24, 192.168.3.0/24
Endpoint = 26.115.154.67:8181
PersistentKeepalive = 25
````
# VpnClient

`Get-Command -Module VpnClient` \
`Add-VpnConnection -Name "vpn-failon" -ServerAddress "26.115.154.67" -TunnelType L2TP -L2tpPsk "123098" -EncryptionLevel "Потрібен" -AuthenticationMethod MSChapv2 -RememberCred
`-TunnelType PPTP/L2TP/SSTP/IKEv2/Automatic` \
`-L2tpPsk` використовувати спільний ключ для аутентифікації (без параметра, для L2TP аутентифікації використовується сертифікат) \
`-AuthenticationMethod Pap/Chap/MSChapv2/Eap/MachineCertificate` \
`-EncryptionLevel NoEncryption/Optional/Required/Maximum/Custom` \
`-SplitTunneling` загортати весь трафік через VPN-тунель (включення Use default gateway on remote network у налаштуваннях параметра VPN адаптера) \
`-UseWinlogonCredential` використовувати облікові дані поточного користувача для аутентифікації на сервері VPN \
`-RememberCredential` дозволити зберігати облікові дані для VPN підключення (обліковий запис та пароль зберігаються в диспетчер облікових даних Windows після першого успішного підключення) \
`-DnsSuffix domain.local` \
`-AllUserConnection` дозволити використовувати VPN підключення для всіх користувачів комп'ютера (зберігається в конфігураційний файл: C:\ProgramData\Microsoft\Network\Connections\Pbk\rasphone.pbk)

`Install-Module -Name VPNCredentialsHelper` модуль для збереження логіну та пароля в Windows Credential Manager для VPN підключення \
`Set-VpnConnectionUsernamePassword -connectionname vpn-failon -username user1 -password password`

`rasdial "vpn-failon"` підключитися \
`Get-VpnConnection -AllUserConnection | select *` список VPN підключення, доступних для всіх користувачів, налаштування та поточний статус підключення (ConnectionStatus) \
`Add-VpnConnectionRoute -ConnectionName vpn-failon -DestinationPrefix 192.168.3.0/24 –PassThru` динамічно додати до таблиці маршрутизації маршрут, який буде активний при підключенні до VPN \
`Remove-VpnConnection -Name vpn-failon -AllUserConnection -Force` видалити

`Set-VpnConnection -Name "vpn-failon" -SplitTunneling $True` включити роздільне тунелювання \
`Add-VpnConnectionRoute -ConnectionName "vpn-failon" -DestinationPrefix 172.22.22.0/24` налаштувати маршрутизацію до вказаної підмережі через VPN-з'єднання \
`(Get-VpnConnection -ConnectionName "vpn-failon").routes` відобразити таблицю маршрутизації для зазначеного з'єднання \
`Remove-VpnConnectionRoute -ConnectionName "vpn-failon" -DestinationPrefix "172.22.23.0/24"`

# Proxy

`$user = "lifailon"` \
`$pass = "Proxy"` \
`$SecureString = ConvertTo-SecureString $pass -AsPlainText -Force` \
`$Credential = New-Object System.Management.Automation.PSCredential($user, $SecureString)` \
`[System.Net.Http.HttpClient]::DefaultProxy = New-Object System.Net.WebProxy("http://192.168.3.100:9090")` \
`[System.Net.Http.HttpClient]::DefaultProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials` \
`[System.Net.Http.HttpClient]::DefaultProxy.Credentials = $Credential` \
`Invoke-RestMethod http://ifconfig.me/ip` \
`Invoke-RestMethod https://kinozal.tv/rss.xml`

# OpenSSH

`Get-WindowsCapability-Online | ? Name -like 'OpenSSH.Client*'` \
`Add-WindowsCapability -Online -Name OpenSSH.Client*` \
`dism /Online /Add-Capability /CapabilityName:OpenSSH.Client~~~~0.0.1.0` \
`iwr https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.2.2.0p1-Beta/OpenSSH-Win64-v9.2.2.0.msi -OutFile $home\Downloads\OpenSSH-Win64- v9.2.2.0.msi` завантажити \
`msiexec /i $home\Downloads\OpenSSH-Win64-v9.2.2.0.msi` встановити msi пакет \
`Set-Service sshd -StartupType Automatic` \
`Get-NetTCPConnection | where LocalPort -eq 22`\
`New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22` \
`Get-NetFirewallRule -Name *ssh*` \
`Start-Process notepad++ C:\Programdata\ssh\sshd_config` конфігураційний файл \
`GSSAPIAuthentication yes` включити Kerberos автентифікацію (через AD) \
`SyslogFacility LOCAL0` включити локальне ведення журналу до файлу (C:\ProgramData\ssh\logs\sshd.log) \
`LogLevel INFO` \
`Restart-Service sshd` \
`ssh -K $srv` виконати Kerberos автентифікацію \
`ssh Lifailon@192.168.3.99 -p 22` \
`pwsh -command Get-Service` \
`ssh -L 3101:192.168.3.101:22 -R 3101:192.168.3.101:22 lifailon@192.168.3.101 -p 22` SSH Tunnel lifailon@localhost:3101 -1:19

# WinRM

`Enter-PSSession -ComputerName $srv` підключитися до PowerShell сесії через PSRemoting. Підключення можливе лише за FQDN-ім'ям \
`Invoke-Command $srv -ScriptBlock {Get-ComputerInfo}` виконання команди через PSRemoting \
`$session = New-PSSession $srv` відкрити сесію \
`Get-PSSession` відобразити активні сесії \
`icm -Session $session {$srv = $using:srv}` передати змінну поточної сесії ($using) у віддалену \
`Disconnect-PSSession $session` закрити сесію \
`Remove-PSSession $session` видалити сесію \
`Import-Module -Name ActiveDirectory -PSSession $srv` імпортувати модуль з віддаленого комп'ютера до локальної сесії

### Windows Remote Management Configuration

`winrm quickconfig -quiet` змінить запуск служби WinRM на автоматичний, задасть стандартні налаштування WinRM та додасть винятки для портів у fw \
`Enable-PSRemoting –Force` увімкнути PowerShell Remoting, працює тільки для доменного та приватного мережевих профілів Windows \
`Enable-PSRemoting -SkipNetworkProfileCheck -Force` для налаштування комп'ютера у спільній (public) мережі (працює з версії powershell 6)

`$NetProfiles = Get-NetConnectionProfile` відобразити профілі мережевих підключень \
`Set-NetConnectionProfile -InterfaceIndex $NetProfiles[1].InterfaceIndex -NetworkCategory Private` змінити тип мережі для профілю (DomainAuthenticated/Public) \
`(Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain` перевірити, що комп'ютер додано до домену AD \
`Get-Service WinRM | Set-Service -StartupType AutomaticDelayedStart` відкладений запуск \
`Get-Service -Name winrm -RequiredServices` статус залежних служб \
`New-NetFirewallRule -Profile Any -DisplayName "WinRM HTTP" -Direction Inbound -Protocol TCP -LocalPort 5985,5986` \
`Test-NetConnection $srv -port 5895` перевірити порт \
`Test-WSMan $srv -ErrorAction Ignore` перевірити роботу WinRM на віддаленому комп'ютері (ігнорувати виведення помилок для скрипту) або локально (localhost)

`$Cert = New-SelfSignedCertificate -CertStoreLocation Cert:\LocalMachine\My -DnsName "$env:computername" -FriendlyName "WinRM HTTPS Certificate" -NotAfter (Get-Date).AddYears(5)` створити самопідписаний серти
`$Thumbprint = $Cert.Thumbprint` забрати відбиток \
`New-Item -Path WSMan:\Localhost\Listener -Transport HTTPS -Address * -CertificateThumbprint $Thumbprint -Name WinRM_HTTPS_Listener -Force` створити прослуховувач \
`New-NetFirewallRule -DisplayName 'WinRM HTTPS' -Profile Domain,Private -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5986` відкрити порт у fw
````
$selector_set = @{
Address = "*"
Transport = "HTTPS"
}
$value_set = @{
CertificateThumbprint = "66ABFDA044D8C85135048186E2FDC0DBE6125163"
}
New-WSManInstance -ResourceURI "winrm/config/Listener" -SelectorSet $selector_set -ValueSet $value_set
````
`winrm get winrm/config` відобразити всю конфігурацію (Client/Service) \
`winrm get winrm/config/service/auth` конфігурація авторизації на сервері \
`winrm enumerate winrm/config/listener` поточна конфігурація прослуховувачів WinRM (відображає відбиток сертифіката для HTTPS 5986) \
`Get-ChildItem -Path Cert:\LocalMachine\My\ | where Thumbprint -eq D9356FB774EE0E6206B7D5B59B99102CA5B17BDA | select *` інформація про сертифікат

`ls WSMan:\localhost\Client` конфігурацію клієнта \
`ls WSMan:\localhost\Service` конфігурація сервера \
`ls WSMan:\localhost\Service\auth` список усіх конфігурацій автентифікації WinRM сервера \
`Set-Item -path WSMan:\localhost\Service\auth\basic -value $true` дозволити локальну автентифікацію до поточного сервера \
`ls HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN` налаштування в реєстрі (наприклад, для включення аудентифікації в \Service\auth_basic = 1) \
`Set-Item WSMan:\localhost\Client\TrustedHosts -Value 192.168.* -Force` додати довірені хости в конфігурацію на клієнті, щоб працювала Negotiate автентифікація через NTLM \
`Set-Item WSMan:\localhost\Client\TrustedHosts -Value 192.168.3.100 -Concatenate -Force` додати другий комп'ютер \
`ls WSMan:\localhost\Client\TrustedHosts` \
`Set-Item WSMan:\localhost\Client\AllowUnencrypted $true` включити передачу незашифрованих даних конфігурації клієнта \
`Set-Item WSMan:\localhost\Service\AllowUnencrypted $true` включити передачу незашифрованих даних конфігурації сервера (необхідно бути в private мережі)

`Get-PSSessionConfiguration` перевірити, чи включений PSremoting та вивести список користувачів та груп, яким дозволено підключатися через WinRM \
`Set-PSSessionConfiguration -Name Microsoft.PowerShell -ShowSecurityDescriptorUI` призначити права доступу через дескриптор безпеки поточної сесії (до перезавантаження) \
`(Get-PSSessionConfiguration -Name "Microsoft.PowerShell").SecurityDescriptorSDDL` отримати налаштування дескриптора у форматі SDDL \
`Set-PSSessionConfiguration -Name Microsoft.PowerShell -SecurityDescriptorSDDL $SDDL` застосувати налаштування дескриптора на іншому комп'ютері без використання GUI \

`New-LocalUser "WinRM-Writer" -Password (ConvertTo-SecureString -AsPlainText "123098")` створити користувача \
`Add-LocalGroupMember -Group "Remote Management Users" -Member "WinRM-Writer"` додати користувача WinRM-Writer до локальної групи доступу "Користувачі віддаленого керування" \
`cmdkey /add:192.168.3.99 /user:WinRM-Writer /pass:123098` зберегти пароль у CredentialManager
`cmdkey /list` \
`Import-Module CredentialManager` \
`Add-Type -AssemblyName System.Web` \
`New-StoredCredential -Target 192.168.3.99 -UserName WinRM-Writer -Password 123098 -Comment WinRM` зберегти пароль в CredentialManager (з PS5) \
`Get-StoredCredential -AsCredentialObject` \
`$cred = Get-StoredCredential -Target 192.168.3.99` \
`Enter-PSSession -ComputerName 192.168.3.99 -Credential $cred -Authentication Negotiate` \
`Enter-PSSession -ComputerName 192.168.3.99 -Credential $cred -Authentication Basic -Port 5985` працює при відключенні allowunencrypted на стороні сервера та клієнта \
`winrs -r:http://192.168.3.100:5985/wsman -u:WinRM-Writer -p:123098 ipconfig` передати команду через winrs (-?) \
`winrs -r:https://192.168.3.100:5985/wsman -u:WinRM-Writer -p:123098 -ssl ipconfig` через https \
`pwsh -Command "Install-Module -Name PSWSMan"` встановити модуль для використання в Linux системі

### Kerberos

`.\CheckMaxTokenSize.ps1 -Principals login -OSEmulation $true -Details $true` дізнатися розмір токена користувача в домені \
`Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters | select maxtokensize` максимальний розмір токена на сервері \
`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\HTTP\Parameters` змінити розміру, якщо заголовок пакета автентифікації перевищує 16 Кб (через велику кількість груп) \
`MaxFieldLength збільшити до 0000ffff (65535)` \
`MaxRequestBytes збільшити до 0000ffff (65535)`

# PackageManagement

`Import-Module PackageManagement` імпортувати модуль \
`Get-Module PackageManagement` інформація про модуль \
`Get-Command -Module PackageManagement` відобразити всі командлети модуля \
`Get-Package` відобразити всі встановлені пакети PowerShellGallery \
`Get-Package -ProviderName msi,Programs` список встановлених програм
`[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12` включити використання протоколу TLS 1.2 (якщо не відключено протоколи TLS 1.0 і 1.1) \
`Find-PackageProvider` пошук провайдерів \
`Install-PackageProvider PSGallery -force` встановити джерело \
`Install-PackageProvider NuGet-force` \
`Install-PackageProvider Chocolatey -force` \
`Get-PackageSource` джерела встановлення пакетів \
`Set-PackageSource -Name PSGallery -Trusted` за замовчуванням \
`Find-Package -Name *Veeam* -Source PSGallery` пошук пакетів із зазначенням джерела \
`Install-Package -Name VeeamLogParser -ProviderName PSGallery -scope CurrentUser` \
`Get-Command *Veeam*` \
`Import-Module -Name VeeamLogParser` завантажити модуль \
`Get-Module VeeamLogParser | select -ExpandProperty ExportedCommands` відобразити список функцій

### winget

[Source](https://github.com/microsoft/winget-cli)
[Web] (https://winget.run)

`winget list` список встановлених пакетів \
`winget search VLC` знайти пакет \
`winget show VideoLAN.VLC` інформація про пакет \
`winget show VideoLAN.VLC --versions` список доступних версій в репозиторії \
`winget install VideoLAN.VLC` встановити пакет \
`winget uninstall VideoLAN.VLC` видалити пакет \
`winget download jqlang.jq` завантажити пакет (https://github.com/jqlang/jq/releases/download/jq-1.7/jq-windows-amd64.exe) \
`winget install jqlang.jq` додає у змінне середовище та псевдонім командного рядка jq \
`winget uninstall jqlang.jq`

### jqlang-install
```PowerShell
[uri]$url = $($(irm https://api.github.com/repos/jqlang/jq/releases/latest).assets.browser_download_url -match "windows-amd64").ToString() # отримати версію останній на GitHub
irm $url -OutFile "C:\Windows\System32\jq.exe" # завантажити jq.exe
````
### Scoop

`Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` \
`irm get.scoop.sh | iex` установка \
`scoop help` \
`scoop search jq` \
`scoop info jq` \
`(scoop info jq).version`\
`scoop cat jq` \
`scoop download jq` C:\Users\lifailon\scoop\cache \
`scoop install jq` C:\Users\lifailon\scoop\apps\jq\1.7 \
`scoop list` \
`(scoop list).version`\
`scoop uninstall jq`

### Chocolatey
```PowerShell
Set-ExecutionPolicy Bypass-Scope Process-Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
````
`choco -v` \
`choco-help` \
`choco list` \
`choco install adobereader`

# NuGet

`Invoke-RestMethod https://dist.nuget.org/win-x86-commandline/latest/nuget.exe -OutFile "$home\Documents\nuget.exe"` \
`Invoke-Expression "$home\Documents\nuget.exe search Selenium.WebDriver"` \
`Invoke-Expression "$home\Documents\nuget.exe install Selenium.WebDriver"` \
`Get-Item $home\Documents\*Selenium*`

`& "$home\Documents\nuget.exe" list console-translate` \
`$nuget_api_key = "<API-KEY>"` \
`$source = "https://api.nuget.org/v3/index.json"` \
`$Name = "Console-Translate"` \
`$path = "$home\Documents\$Name"` \
`New-Item -Type Directory $path` \
`Copy-Item "$home\Documents\Git\$Name\$Name\0.2\*" "$path\"` \
`Copy-Item "$home\Documents\Git\$Name\LICENSE" "$path\"` \
`Copy-Item "$home\Documents\Git\$Name\README.md" "$path\"`
```PowerShell
'<?xml version="1.0"?>
<package>
<metadata>
<id>Console-Translate</id>
<version>0.2.2</version>
<authors>Lifailon</authors>
<owners>Lifailon</owners>
<description>Кросс-платформа клієнта для перетворення тексту в консолі, використовує API Google (edded public free token), MyMemory and DeepLX (no token required)</description>
<tags>PowerShell, Module, Translate, api</tags>
<projectUrl>https://github.com/Lifailon/Console-Translate</projectUrl>
<contentFiles>
<files include="Console-Translate.psm1" buildAction="Content" />
<files include="Console-Translate.psd1" buildAction="Content" />
<files include="lang-iso-639-1.csv" buildAction="Content" />
<files include="README.md" buildAction="Content" />
<files include="LICENSE" buildAction="Content" />
</contentFiles>
</metadata>
</package>' > "$path\$Name.nuspec"
````
`Set-Location $path` \
`& "$home\Documents\nuget.exe" pack "$path\$Name.nuspec"` \
`& "$home\Documents\nuget.exe" push "$path\$Name.0.2.2.nupkg" -ApiKey $nuget_api_key -Source $source` \
`& "$home\Documents\nuget.exe" push "$path\$Name.0.2.2.nupkg" -ApiKey $nuget_api_key -Source $source -SkipDuplicate`

`Install-Package Console-Translate -Source nuget.org` \
`Get-Package Console-Translate | select *`

`Register-PSRepository -Name "NuGet" -SourceLocation "https://www.nuget.org/api/v2" -InstallationPolicy Trusted` \
`Get-PSRepository` \
`Find-Module -Name Console-Translate` \
`Install-Module Console-Translate -Repository NuGet`

`& "$home\Documents\nuget.exe" delete Console-Translate 0.2.0 -Source https://api.nuget.org/v3/index.json -ApiKey $nuget_api_key -NoPrompt`

# Git

`git --version` \
`git config --global user.name "Lifailon"` додати ім'я для коммітів \
`git config --global user.email "lifailon@yandex.ru"` \
`git config --global --edit` \
`ssh-keygen -t rsa -b 4096` \
Get-Service | where name -match "ssh-agent" | Set-Service -StartupType Automatic` \
Get-Service | where name -match "ssh-agent" | Start-Service`\
Get-Service | where name -match "ssh-agent" | select Name,Status,StartType` \
`ssh-agent` \
`ssh-add C:\Users\Lifailon\.ssh\id_rsa` \
`cat ~\.ssh\id_rsa.pub | Set-Clipboard` copy to https://github.com/settings/keys\
`cd $home\Documents\Git` \
`git clone git@github.com:Lifailon/PowerShell-Commands` \
`cd PowerShell-Commands` \
`git grep powershell` пошук тексту у файлах \
`git pull` синхронізувати зміни зі сховища
`git status` відобразити статус змін файлів \
`git diff` відобразити зміни строком \
`git add .` додати (проіндексувати) зміни у всіх файлах \
`git commit -m "added file and changed file"` зберегти зміни з коментарем \
`git push` синхронізувати локальні зміни з репозиторієм
`git branch dev` створити нову гілку \
`git switch dev` перейти на іншу гілку \
`git push --set-upstream origin dev` додати гілку \
`git branch -d dev` видалити гілку \
`git diff rsa` порівняти файли поточної гілки з файлами у вказаній гілці rsa \
`git merge dev` злиття поточної гілки (rsa/master) із зазначеною (dev) \
`git log --oneline --all` лог коммітів \
`git log --graph` комміти та прямування гілок \
`git show d01f09dead3a6a8d75dda848162831c58ca0ee13` відобразити докладний лог за номером комміта \
`git checkout filename` відкотити зміни, якщо не було команди add \
`git checkout d01f09dead3a6a8d75dda848162831c58ca0ee13` переключити локальні файли робочої копії на вказаний коміт (змінити HEAD на вказаний коміт) \
`git reset HEAD filename` відкотити зміни останнього індексу, якщо був add але не було commit, тим самим повернутися до останньої зафіксованої версії (комміту) і потім виконати checkout \
`git reset --mixed HEAD filename` зміни, що містяться у скасовуваному коміті, не повинні зникнути, вони будуть збережені у вигляді локальних змін у робочій копії \
`git restore filename` скасувати всі локальні зміни в робочій копії \
`git restore --source d01f09dead3a6a8d75dda848162831c58ca0ee13 filename` відновити файл на вказану версію по хешу індентифікатора комміта \
`git revert HEAD --no-edit` скасувати останній коміт без вказівки коментаря (події записуються в git log) \
`git reset --hard d01f09dead3a6a8d75dda848162831c58ca0ee13` видалити всі коміти до вказаного (і відкотитися до нього)

# DSC

`Import-Module PSDesiredStateConfiguration` \
`Get-Command -Module PSDesiredStateConfiguration` \
`(Get-Module PSDesiredStateConfiguration).ExportedCommands` \
`Get-DscLocalConfigurationManager`

`Get-DscResource` \
`Get-DscResource -Name File -Syntax` https://learn.microsoft.com/ru-ua/powershell/dsc/reference/resources/windows/fileresource?view=dsc-1.1

`Ensure = Present` налаштування має бути включене (каталог повинен бути присутнім, процес повинен бути запущений, якщо ні – створити, запустити) \
`Ensure = Absent` налаштування має бути вимкнене (каталога бути не повинно, процес не повинен бути запущений, якщо ні – видалити, зупинити)
```PowerShell
Configuration TestConfiguraion
{
Ctrl+Space
}

Configuration DSConfigurationProxy
{
Node vproxy-01
{
File CreateDir
{
Ensure = "Present"
Type = "Directory"
DestinationPath = "C:\Temp"
}
Service StopW32time
{
Name = "w32time"
State = "Stopped"` Running
}
		WindowsProcess RunCalc
{
Ensure = "Present"
Path = "C:WINDOWSsystem32calc.exe"
Arguments = ""
}
Registry RegSettings
{
Ensure = "Present"
Key = "HKEY_LOCAL_MACHINE\SOFTWARE\MySoft"
ValueName = "TestName"
ValueData = "TestValue"
ValueType = "String"
}
# 		WindowsFeature IIS
# {
# Ensure = "Present"
# Name = "Web-Server"
# }
}
}
````
`$Path = (DSConfigurationProxy).DirectoryName` \
`Test-DscConfiguration -Path $Path | select *` ResourcesInDesiredState - вже налаштовано, ResourcesNotInDesiredState - не налаштовано (не відповідає) \
`Start-DscConfiguration -Path $Path` \
`Get-Job` \
`$srv = "vproxy-01"` \
`Get-Service -ComputerName $srv | ? name -match w32time # Start-Service`\
`icm $srv {Get-Process | ? ProcessName -match calc} | ft # Stop-Process -Force `\
`icm $srv {ls C:\ | ? name-match Temp} | ft` rm`
```PowerShell
Configuration InstallPowerShellCore {
Import-DscResource -ModuleName PSDesiredStateConfiguration
Node localhost {
Script InstallPowerShellCore {
GetScript = {
return @{
GetScript = $GetScript
}
}
SetScript = {
				[string]$url = $(Invoke-RestMethod https://api.github.com/repos/PowerShell/PowerShell/releases/latest).assets.browser_download_url -match "win-x64.zip"
$downloadPath = "$home\Downloads\PowerShell.zip"
$installPath = "$env:ProgramFiles\PowerShell\7"
Invoke-WebRequest -Uri $url -OutFile $downloadPath
Expand-Archive -Path $downloadPath -DestinationPath $installPath -Force
}
TestScript = {
return Test-Path "$env:ProgramFiles\PowerShell\7\pwsh.exe"
}
}
}
}
````
`$Path = (InstallPowerShellCore).DirectoryName` \
`Test-DscConfiguration -Path $Path` \
`Start-DscConfiguration -Path $path -Wait -Verbose` \
`Get-Job`

# Ansible

`apt -y update && apt -y upgrade` \
`apt -y install ansible` v2.10.8 \
`apt -y install ansible-core` v2.12.0 \
`apt -y install sshpass`

`ansible-galaxy collection install ansible.windows` встановити колекцію модулів \
`ansible-galaxy collection install community.windows` \
`ansible-galaxy collection list | grep windows`\
`ansible-config dump | grep DEFAULT_MODULE_PATH` шлях зберігання модулів

`apt-get -y install python-dev libkrb5-dev krb5-user` пакети для Kerberos аутентифікації \
`apt install python3-pip` \
`pip3 install requests-kerberos` \
`nano /etc/krb5.conf` налаштувати [realms] та [domain_realm] \
`kinit -C support4@domail.local` \
`klist`

`ansible --version` \
`config file = None` \
`nano /etc/ansible/ansible.cfg` файл конфігурації
````
[defaults]
inventory = /etc/ansible/hosts
# uncomment this to disable SSH key host checking
# Вимкнути перевірку ключа ssh (для підключення за допомогою пароля)
host_key_checking = False
````
`nano /etc/ansible/hosts`
````
[us]
pi-hole-01 ansible_host=192.168.3.101
zabbix-01 ansible_host=192.168.3.102
grafana-01 ansible_host=192.168.3.103
netbox-01 ansible_host=192.168.3.104

[all:vars]
ansible_ssh_port=2121
ansible_user=lifailon
ansible_password=123098
path_user=/home/lifailon
ansible_python_interpreter=/usr/bin/python3

[ws]
huawei-book-01 ansible_host=192.168.3.99
plex-01 ansible_host=192.168.3.100

[ws:vars]
ansible_port=5985
#ansible_port=5986
ansible_user=Lifailon
#ansible_user=support4@DOMAIN.LOCAL
ansible_password=123098
ansible_connection=winrm
ansible_winrm_scheme=http
ansible_winrm_transport=basic
#ansible_winrm_transport=kerberos
ansible_winrm_server_cert_validation=ignore
validate_certs=false

[win_ssh]
huawei-book-01 ansible_host=192.168.3.99
plex-01 ansible_host=192.168.3.100

[win_ssh:vars]
ansible_python_interpreter=C:\Users\Lifailon\AppData\Local\Programs\Python\Python311\` додати змінне середовище інтерпретатора Python у Windows
ansible_connection=ssh
#ansible_shell_type=cmd
ansible_shell_type=powershell
````
`ansible-inventory --list` перевірити конфігурацію (читає у форматі JSON) або YAML (-y) з переглядом всіх змінних

# Modules

`ansible us -m ping` \
`ansible win_ssh -m ping` \
`ansible us -m shell -a "uptime && df -h | grep lv"` \
`ansible us-m setup | grep -iP "mem|proc"` інформація про залізо \
`ansible us -m apt -a "name=mc" -b` підвищити привілеї sudo(-b) \
`ansible us -m service -a "name=ssh state=restarted enabled=yes" -b` перезапустити службу \
`echo "echo test" > test.sh` \
`ansible us -m copy -a "src=test.sh dest=/root mode=777" -b` \
`ansible us -a "ls /root" -b `\
`ansible us -a "cat /root/test.sh" -b`

`ansible-doc-l | grep win_` список усіх модулів Windows (https://docs.ansible.com/ansible/latest/collections/ansible/windows/) \
`ansible ws -m win_ping` windows модуль \
`ansible ws -m win_ping -u WinRM-Writer` вказати логін \
`ansible ws -m setup` зібрати докладну інформацію про систему \
`ansible ws -m win_whoami` інформація про права доступу, групи доступу \
`ansible ws -m win_shell -a '$PSVersionTable'` \
`ansible ws -m win_shell -a 'Get-Service | where name -match "ssh|winrm"'` \
`ansible ws -m win_service -a "name=sshd state=stopped"` \
`ansible ws -m win_service -a "name=sshd state=started"`

### win_shell (vars/debug)

`nano /etc/ansible/PowerShell-Vars.yml`
````
- hosts: ws
` Вказати колекцію модулів
collections:
- ansible.windows
` Поставити змінні
vars:
SearchName: PermitRoot
tasks:
- name: Get port ssh
win_shell: |
Get-Content "C:\Programdata\ssh\sshd_config" | Select-String "{{SearchName}}"
` Передати висновок у змінну
register: command_output
- name: Output port ssh
Вивести змінну на екран
debug:
var: command_output.stdout_lines
````
`ansible-playbook /etc/ansible/PowerShell-Vars.yml` \
`ansible-playbook /etc/ansible/PowerShell-Vars.yml --extra-vars "SearchName='LogLevel|Syslog'"` передати змінну

### win_powershell

`nano /etc/ansible/powershell-param.yml`
````
- hosts: ws
tasks:
- name: Run PowerShell script with parameters
ansible.windows.win_powershell:
parameters:
Path: C:\Temp
Force: true
script: |
[CmdletBinding()]
param (
[String]$Path,
[Switch]$Force
)
New-Item -Path $Path -ItemType Directory -Force:$Force
````
`ansible-playbook /etc/ansible/powershell-param.yml`

### win_chocolatey

`nano /etc/ansible/setup-adobe-acrobat.yml`
````
- hosts: ws
tasks:
- name: Install Acrobat Reader
win_chocolatey:
name: adobereader
state: present
````
`ansible-playbook /etc/ansible/setup-adobe-acrobat.yml`

`nano /etc/ansible/setup-openssh.yml`
````
- hosts: ws
tasks:
- name: install the Win32-OpenSSH service
win_chocolatey:
name: openssh
package_params: /SSHServerFeature
state: present
````
`ansible-playbook /etc/ansible/setup-openssh.yml`

### win_regedit

`nano /etc/ansible/win-set-shell-ssh-ps7.yml`
````
- hosts: ws
tasks:
- name: Натисніть на більшу значок до PowerShell 7 для Windows OpenSSH
win_regedit:
path: HKLM:\SOFTWARE\OpenSSH
name: DefaultShell
` data: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
data: 'C:\Program Files\PowerShell\7\pwsh.exe'
type: string
state: present
````
`ansible-playbook /etc/ansible/win-set-shell-ssh-ps7.yml`

### win_service

`nano /etc/ansible/win-service.yml`
````
- hosts: ws
tasks:
- name: Start service
win_service:
name: sshd
state: started
# state: stopped
# state: restarted
# start_mode: auto
````
`ansible-playbook /etc/ansible/win-service.yml`

### win_service_info

`nano /etc/ansible/get-service.yml`
````
- hosts: ws
tasks:
- name: Get info for a single service
win_service_info:
name: sshd
register: service_info
- name: Print returned information
ansible.builtin.debug:
var: service_info.services
````
`ansible-playbook /etc/ansible/get-service.yml`

### fetch/slurp

`nano /etc/ansible/copy-from-win-to-local.yml`
````
- hosts: ws
tasks:
- name: Retrieve remote file on a Windows host
# Копіювати файл із Windows-системи
ansible.builtin.fetch:
# Прочитати файл (передати в пам'ять у форматі Base64)
# ansible.builtin.slurp:
src: C:\Telegraf\telegraf.conf
dest: /root/telegraf.conf
flat: yes
register: telegraf_conf
- name: Print returned information
ansible.builtin.debug:
msg: "{{ telegraf_conf['content'] | b64decode }}"
````
`ansible-playbook /etc/ansible/copy-from-win-to-local.yml`

### win_copy

`echo "Get-Service | where name -eq vss | Start-Service" > /home/lifailon/Start-Service-VSS.ps1` \
`nano /etc/ansible/copy-file-to-win.yml`
````
- hosts: ws
tasks:
- name: Copy file to win hosts
win_copy:
src: /home/lifailon/Start-Service-VSS.ps1
dest: C:\Users\Lifailon\Desktop\Start-Service-VSS.ps1
````
`ansible-playbook /etc/ansible/copy-file-to-win.yml`

`curl -OL https://github.com/PowerShell/PowerShell/releases/download/v7.3.6/PowerShell-7.3.6-win-x64.msi` \
`nano /etc/ansible/copy-file-to-win.yml`
````
- hosts: ws
tasks:
- name: Copy file to win hosts
win_copy:
src: /home/lifailon/PowerShell-7.3.6-win-x64.msi
dest: C:\Install\PowerShell-7.3.6.msi
````
`ansible-playbook /etc/ansible/copy-file-to-win.yml`

### win_command

`nano /etc/ansible/run-script-ps1.yml`
````
- hosts: ws
tasks:
- name: Run PowerShell Script
win_command: powershell -ExecutionPolicy ByPass -File C:\Users\Lifailon\Desktop\Start-Service-VSS.ps1
````
`ansible-playbook /etc/ansible/run-script-ps1.yml`

### win_package

`nano /etc/ansible/setup-msi-package.yml`
````
- hosts: ws
tasks:
- name: Install MSI Package
win_package:
# path: C:\Install\7z-23.01.msi
path: C:\Install\PowerShell-7.3.6.msi
arguments:
- /quiet
- /passive
- /Norestart
````
`ansible-playbook /etc/ansible/setup-msi-package.yml`

### win_firewall_rule

`nano /etc/ansible/win-fw-open.yml`
````
- hosts: ws
tasks:
- name: Open RDP port
win_firewall_rule:
name: Open RDP port
localport: 3389
action: allow
direction: in
protocol: tcp
state: present
enabled: yes
````
`ansible-playbook /etc/ansible/win-fw-open.yml`

### win_group

`nano /etc/ansible/win-creat-group.yml`
````
- hosts: ws
tasks:
- name: Create a new group
win_group:
name: deploy
description: Deploy Group
state: present
````
`ansible-playbook /etc/ansible/win-creat-group.yml`

### win_group_membership

`nano /etc/ansible/add-user-to-group.yml`
````
- hosts: ws
tasks:
- name: Add a local and domain user to a local group
win_group_membership:
name: deploy
members:
- WinRM-Writer
state: present
````
`ansible-playbook /etc/ansible/add-user-to-group.yml`

### win_user

`nano /etc/ansible/creat-win-user.yml`
````
- hosts: ws
tasks:
- name: Creat user
win_user:
name: test
password: 123098
state: present
groups:
- deploy
````
`ansible-playbook /etc/ansible/creat-win-user.yml`

`nano /etc/ansible/delete-win-user.yml`
````
- hosts: ws
tasks:
- name: Delete user
ansible.windows.win_user:
name: test
state: absent
````
`ansible-playbook /etc/ansible/delete-win-user.yml`

### win_feature

`nano /etc/ansible/install-feature.yml`
````
- hosts: ws
tasks:
- name: Install Windows Feature
win_feature:
name: SNMP-Service
state: present
````
`ansible-playbook /etc/ansible/install-feature.yml`

### win_reboot

`nano /etc/ansible/win-reboot.yml`
````
- hosts: ws
tasks:
- name: Reboot a slow machine that might have lots of updates to apply
win_reboot:
reboot_timeout: 3600
````
`ansible-playbook /etc/ansible/win-reboot.yml`

### win_find

`nano /etc/ansible/win-ls.yml`
````
- hosts: ws
tasks:
- name: Find files in multiple paths
ansible.windows.win_find:
paths:
- D:\Install\OpenSource
patterns: ['*.rar','*.zip','*.msi']
` Файл створений менше 7 днів тому
age: -7d
` Розмір файлу більше 10MB
size: 10485760
Рекурсивний пошук (у дочірніх директоріях)
recurse: true
register: command_output
- name: Output
debug:
var: command_output
````
`ansible-playbook /etc/ansible/win-ls.yml`

### win_uri

`nano /etc/ansible/rest-get.yml`
````
- hosts: ws
tasks:
- name: REST GET request to endpoint github
ansible.windows.win_uri:
url: https://api.github.com/repos/Lifailon/pSyslog/releases/latest
register: http_output
- name: Output
debug:
var: http_output
````
`ansible-playbook /etc/ansible/rest-get.yml`

### win_updates

`nano /etc/ansible/win-update.yml`
````
- hosts: ws
tasks:
- name: Install only particular updates based on the KB numbers
ansible.windows.win_updates:
category_names:
- SecurityUpdates
- CriticalUpdates
- UpdateRollups
- Drivers
` Фільтрування
accept_list:
` - KB2267602
` Пошук оновлень
state: searched
` Завантажити оновлення
` state: downloaded
` Встановити оновлення
state: installed
log_path: C:\Ansible-Windows-Upadte-Log.txt
reboot: false
register: wu_output
- name: Output
debug:
var: wu_output
````
`ansible-playbook /etc/ansible/win-update.yml`

### win_chocolatey

https://chocolatey.org/install \
https://community.chocolatey.org/api/v2/package/chocolatey \
https://docs.chocolatey.org/en-us/guides/organizations/organizational-deployment-guide
````
- name: Ensure Chocolatey installed from internal repo
win_chocolatey:
name: chocolatey
state: present
	# source: URL-адреса внутрішнього репозиторію
source: https://community.chocolatey.org/api/v2/ChocolateyInstall.ps1
````
# GigaChat

### 1. Встановлення сертифікатів:

`Invoke-WebRequest "https://gu-st.ru/content/lending/russian_trusted_root_ca_pem.crt" -OutFile "$home\Downloads\russian_trusted_root_ca.cer"` скачати сертифікат мінцифри \
`Invoke-WebRequest "https://gu-st.ru/content/lending/russian_trusted_sub_ca_pem.crt" -OutFile "$home\Downloads\russian_trusted_sub_ca.cer"` \
`Import-Certificate -FilePath "$home\Downloads\russian_trusted_root_ca.cer" -CertStoreLocation "Cert:\CurrentUser\Root"` встановити сертифікат мінцифри \
`Import-Certificate -FilePath "$home\Downloads\russian_trusted_sub_ca.cer" -CertStoreLocation "Cert:\CurrentUser\CA"`

### 2. Авторизація по Sber ID та генерація нових авторизаційних даних для отримання токена: https://developers.sber.ru/studio (час життя 30 хвилин)

### 3. Формування авторизаційних даних у форматі Base64 з Client ID та Client Secret:
```PowerShell
$Client_ID = "7e6d2f9f-825e-49b7-98f4-62fbb7506427" # [System.Guid]::Parse("7e6d2f9f-825e-49b7-98f4-62fbb7506427")
$Client_Secret = "c35113ee-6757-47ba-9853-ea1d0d9db1ef" # [System.Guid]::Parse("c35113ee-6757-47ba-9853-ea1d0d9db1ef")
$Client_Join = $Client_ID+":"+$Client_Secret # об'єднуємо два UUID в один рядок, розділяючи їх символом ':'
$Bytes = [System.Text.Encoding]::UTF8.GetBytes($Client_Join) # перетворюємо рядок на масив байт
$Cred_Base64 = [Convert]::ToBase64String($Bytes) # кодуємо байти у рядок Base64
````
### 4. Отримання токена:

`$Cred_Base64 = "N2U2ZDJmOWYtODI1ZS00OWI3LTk4ZjQtNjJmYmI3NTA2NDI3OmIyYzgwZmZmLTEzOGUtNDg1Mi05MjgwLWE2MGI4NTc0YTM2MQ
`$UUID = [System.Guid]::NewGuid()` генеруємо UUID для журналування вхідних дзвінків та розбору інцидентів
```PowerShell
$url = "https://ngw.devices.sberbank.ru:9443/api/v2/oauth"
$headers = @{
"Authorization" = "Basic $Cred_Base64"
"RqUID" = "$UUID"
"Content-Type" = "application/x-www-form-urlencoded"
}
$body = @{
scope = "GIGACHAT_API_PERS"
}
$GIGA_TOKEN = $(Invoke-RestMethod -Uri $url -Method POST -Headers $headers -Body $body).access_token
````
### 5. Параметри:
```PowerShell
[string]$content = "Порахуй суму чисел: 22+33"
[string]$role = "user" # роль автора повідомлення (user/assistant/system)
[float]$temperature = 0.7 # температура вибірки в діапазоні від 0 до 2. Чим вище значення, тим більш випадковою буде відповідь моделі.
[float]$top_p = 0.1 # використовується як альтернатива temperature і змінюється в діапазоні від 0 до 1. Задає ймовірнісну масу токенів, які повинна враховувати модель. Так, якщо передати значення 0.1, модель враховуватиме лише токени, чия ймовірна маса входить у верхні 10%.
[int64]$n = 1 # кількість варіантів відповідей (1..4), які потрібно згенерувати для кожного вхідного повідомлення
[int64]$max_tokens = 512 # максимальна кількість токенів, які будуть використані для створення відповідей
[boolean]$stream = $false # надсилати повідомлення частинами потоку
````
### 6. Складання запитів:
```PowerShell
$url = "https://gigachat.devices.sberbank.ru/api/v1/chat/completions"
$headers = @{
"Authorization" = "Bearer $GIGA_TOKEN"
"Content-Type" = "application/json"
}

$(Invoke-RestMethod -Uri "https://gigachat.devices.sberbank.ru/api/v1/models" -Headers $headers).data # список доступних моделей

$body = @{
model = "GigaChat:latest"
messages = @(
@{
role = $role
content = $content
}
)
temperature = $temperature
	n = $n
	max_tokens = $max_tokens
	stream = $stream
} | ConvertTo-Json
$Request = Invoke-RestMethod -Method POST -Uri $url -Headers $headers -Body $body
$Request.choices.message.content
````
## Curl

### Встановлення сертифікатів в Ubuntu:

`wget https://gu-st.ru/content/lending/russian_trusted_root_ca_pem.crt` \
`wget https://gu-st.ru/content/lending/russian_trusted_sub_ca_pem.crt` \
`mkdir /usr/local/share/ca-certificates/russian_trusted` \
`cp russian_trusted_root_ca_pem.crt russian_trusted_sub_ca_pem.crt /usr/local/share/ca-certificates/russian_trusted` \
`update-ca-certificates -v` \
`wget -qS --spider --max-redirect=0 https://www.sberbank.ru`

### Отримання токена:
``` Bash
Cred_Base64="N2U2ZDJmOWYtODI1ZS00OWI3LTk4ZjQtNjJmYmI3NTA2NDI3OmIyYzgwZmZmLTEzOGUtNDg1Mi05MjgwLWE2MGI4NTc0YTM2MQ=
UUID=$(uuidgen)
GIGA_TOKEN=$(curl -s --location --request POST "https://ngw.devices.sberbank.ru:9443/api/v2/oauth" \
--header "Authorization: Basic $Cred_Base64" \
--header "RqUID: $UUID" \
--header "Content-Type: application/x-www-form-urlencoded" \
--data-urlencode 'scope=GIGACHAT_API_PERS' | jq -r .access_token)
````
`curl -s --location "https://gigachat.devices.sberbank.ru/api/v1/models" --header "Authorization: Bearer $GIGA_TOKEN" | jq.` для перевірки

### Складання запиту:
``` Bash
request=$(curl -s https://gigachat.devices.sberbank.ru/api/v1/chat/completions \
-H "Content-Type: application/json" \
-H "Authorization: Bearer $GIGA_TOKEN" \
-d' {
"model": "GigaChat:latest",
"messages": [
{
"role": "user",
"content": "Коли вже ІІ захопить цей світ?"
}
],
"temperature": 0.7
}')
echo $request | jq -r .choices[].message.content
````
# YandexGPT

## Отримати OAuth-Token:

https://cloud.yandex.ru/ru/docs/iam/operations/iam-token/create час життя IAM-токена не більше 12 годин \
`yandexPassportOauthToken="y0_AgAAAAAGaLFLAATuwQAAAAD3xtRLQE4hvlazQ5euKO43XXXXXXXXXXX"` для bash \
`$yandexPassportOauthToken = "y0_AgAAAAAGaLFLAATuwQAAAAD3xtRLQE4hvlazQ5euKO43XXXXXXXXXXX"` для PowerShell

## Обмінювати OAuth-Token на IAM-Token:

`IAM_TOKEN=$(curl -s -d "{\"yandexPassportOauthToken\":\"$yandexPassportOauthToken\"}" "https://iam.api.cloud.yandex.net/iam/v1/tokens" | jq - r .iamToken)` \
`$IAM_TOKEN = $(Invoke-RestMethod -Method POST -Uri "https://iam.api.cloud.yandex.net/iam/v1/tokens" -Body $(@{yandexPassportOauthToken = "$yandexPassportOauthToken"} | Convert -Json -Compress)).iamToken`

## Отримати FOLDER_ID:
``` Bash
CLOUD_ID=$(curl -s -H "Authorization: Bearer $IAM_TOKEN" https://resource-manager.api.cloud.yandex.net/resource-manager/v1/clouds | jq -r .clouds[].id) # отримати cloud id
curl -s --request GET -H "Authorization: Bearer $IAM_TOKEN" https://resource-manager.api.cloud.yandex.net/resource-manager/v1/folders -d "{\"cloudId\": \ "$CLOUD_ID\"}" # отримати список директорій у хмарі
curl -s --request POST -H "Authorization: Bearer $IAM_TOKEN" https://resource-manager.api.cloud.yandex.net/resource-manager/v1/folders -d "{\"cloudId\": \ "$CLOUD_ID\", \"name\": \"test\"}" # створити директорію в хмарі
FOLDER_ID=$(curl -s --request GET -H "Authorization: Bearer $IAM_TOKEN" https://resource-manager.api.cloud.yandex.net/resource-manager/v1/folders -d '{"cloudId" : "b1gf9n6heihqj0pt5piu"}' | jq -r '.folders[] | select(.name == "test") | .id') # забрати id директорії
````
```PowerShell
$CLOUD_ID = $(Invoke-RestMethod -Method Get -Uri "https://resource-manager.api.cloud.yandex.net/resource-manager/v1/clouds" -Headers @{"Authorization"="Bearer $IAM_TOKEN "; "Content-Type"="application/json"}).clouds.id
$FOLDER_ID = $(Invoke-RestMethod -Method Get -Uri "https://resource-manager.api.cloud.yandex.net/resource-manager/v1/folders" -Headers @{"Authorization"="Bearer $IAM_TOKEN "; "Content-Type"="application/json"} -Body (@{"cloudId"=$CLOUD_ID} | ConvertTo-Json)).folders | Where-Object name -eq test | Select-Object -ExpandProperty id
````
### Складання запиту:
``` Bash
model="gpt://$FOLDER_ID/yandexgpt/latest" # https://cloud.yandex.ru/ru/docs/yandexgpt/concepts/models
body=$(cat <<EOF
{
"modelUri": "$model",
"completionOptions": {
"stream": false,
"temperature": 0.6,
"maxTokens": 2000
},
"messages": [
{
"role": "user",
"text": "Порахуй суму 22+33"
}
]
}
EOF)
curl --request POST \
-H "Content-Type: application/json" \
-H "Authorization: Bearer $IAM_TOKEN" \
-H "x-folder-id: $FOLDER_ID" \
-d "$body" \
"https://llm.api.cloud.yandex.net/foundationModels/v1/completion"
````
```PowerShell
$model = "gpt://$FOLDER_ID/yandexgpt/latest"
$body = @"
{
"modelUri": "$model",
"completionOptions": {
"stream": false,
"temperature": 0.6,
"maxTokens": 2000
},
"messages": [
{
"role": "user",
"text": "Порахуй суму 22+33"
}
]
}
"@
Invoke-RestMethod -Method POST -Uri "https://llm.api.cloud.yandex.net/foundationModels/v1/completion" -Headers @{"Content-Type"="application/json"; "Authorization"="Bearer $IAM_TOKEN"; "x-folder-id"="$FOLDER_ID"} -Body $body
````
# SuperAGI

https://github.com/TransformerOptimus/SuperAGI \
https://models.superagi.com/playground/generate \
https://documenter.getpostman.com/view/30119783/2s9YR3cFJG
``` Bash
SUPERAGI_API_KEY="31f72164129XXXXX"
prompt="Порахуй суму 22+33, дай тільки відповідь без зайвого тексту"
request=$(curl -s -X POST 'https://api.superagi.com/v1/generate/65437cbf227a4018516ad1ce' \
-H 'Content-Type: application/json' \
-H "Authorization: Bearer $SUPERAGI_API_KEY" \
-d' {
"prompt": ["$prompt"],
"max_tokens": 500,
"temperature": 0.9,
"top_p": 0.15,
"repetition_penalty": 0,
"best_of": 1.05,
"top_k": 50,
"stream": false
}')
echo $request | sed "s/data: //" | jq -r .choices[].text
````
```PowerShell
$SUPERAGI_API_KEY = "31f72164129XXXXX"
$prompt = "Порахуй суму 22+33, дай тільки відповідь без зайвого тексту"
$request = Invoke-RestMethod -Method Post -Uri 'https://api.superagi.com/v1/generate/65437cbf227a4018516ad1ce' -Headers @{
'Content-Type' = 'application/json'
'Authorization' = "Bearer $SUPERAGI_API_KEY"
} -Body (@ {
prompt = @($prompt)
max_tokens = 500
Temperature = 0.9
top_p = 0.15
repetition_penalty = 0
best_of = 1.05
top_k = 50
stream = $false
} | ConvertTo-Json)
$($request -replace "^data: " | ConvertFrom-Json).choices.text
````
# Replicate

https://replicate.com/stability-ai/stable-diffusion/examples?input=http
``` Bash
REPLICATE_API_TOKEN="r8_STyeUNXiGonkLfxE1FSKaqll26lXXXXXXXXXX"
prompt="Жираф у смужку зебри"
request = $ (curl -s -X POST \
-H "Authorization: Token $REPLICATE_API_TOKEN" \
-H "Content-Type: application/json" \
-d $'{
"version": "ac732df83cea7fff18b8472768c88ad041fa750ff7682a21affe81863cbe77e4",
"input": {
"prompt": "$prompt"
}
}' \
https://api.replicate.com/v1/predictions)
request_url=$(echo $request | jq -r .urls.get)
response_status=$(curl -s -H "Authorization: Token $REPLICATE_API_TOKEN" $request_url | jq -r .status)
while [[ $response_status != succeeded ]]; do
response_status=$(curl -s -H "Authorization: Token $REPLICATE_API_TOKEN" $request_url | jq -r .status)
done
curl -s -H "Authorization: Token $REPLICATE_API_TOKEN" $request_url | jq -r .output[]
````
```PowerShell
$REPLICATE_API_TOKEN = "r8_STyeUNXiGonkLfxE1FSKaqll26lXXXXXXXXXX"
$prompt = "Жираф у смужку зебри"
$body = @{
version = "ac732df83cea7fff18b8472768c88ad041fa750ff7682a21affe81863cbe77e4"
input = @{
prompt = $prompt
}
} | ConvertTo-Json
$headers = @{
"Authorization" = "Token $REPLICATE_API_TOKEN"
"Content-Type" = "application/json"
}
$request = Invoke-RestMethod -Uri "https://api.replicate.com/v1/predictions" -Method POST -Body $body -Headers $headers
$response = Invoke-RestMethod $($request.urls.get) -Headers @{"Authorization" = "Token $REPLICATE_API_TOKEN"}
while ($response.status -ne "succeeded") {
$response = Invoke-RestMethod $($request.urls.get) -Headers @{"Authorization" = "Token $REPLICATE_API_TOKEN"}
}
$response.output
````
# Google-API

### Google-Translate
```PowerShell
$Key = "<TOKEN_API>" # отримати токен: https://console.cloud.google.com/apis/credentials
$Text = "Ви можете повідомити в правій коронці, щоб довжина всіх повідомлень вимагати такі (це не залежить від суми тексту, що передається)."
$LanguageTarget = "RU"
$LanguageSource = "EN"
$url = "https://translation.googleapis.com/language/translate/v2?key=$key"
$Header = @{
"Content-Type" = "application/json"
}
$Body = @{
"q" = "$Text"
"target" = "$LanguageTarget"
"source" = "$LanguageSource"
} | ConvertTo-Json
$WebClient = New-Object System.Net.WebClient
foreach ($key in $Header.Keys) {
$WebClient.Headers.Add($key, $Header[$key])
}
$Response = $WebClient.UploadString($url, "POST", $Body) | ConvertFrom-Json
$Response.data.translations.translatedText
````
### Google-Search
```PowerShell
$Key = "<TOKEN_API>" # отримати токен: https://developers.google.com/custom-search/v1/overview?hl=ua (пошук користувача JSON API надає 100 пошукових запитів на день безкоштовно)
$cx = "35c78340f49eb474a" # створити пошукову систему https://programmablesearchengine.google.com/controlpanel/all
$Query = "як створити бота discord"
$Lang = "ru"
$Num = 10
$Start = 0
$response = Invoke-RestMethod "https://www.googleapis.com/customsearch/v1?q=$Query&key=$Key&cx=$cx&lr=lang_$Lang&num=$Num&$start=$Start"
$response.items | Select-Object title,snippet,displayLink,link | Format-List
````
# RapidAPI

https://rapidapi.com/ru/neoscrap-net/api/google-search72
```PowerShell
$Key = "<TOKEN_API>"
$headers=@{}
$headers.Add("X-RapidAPI-Key", "$Key")
$headers.Add("X-RapidAPI-Host", "google-search72.p.rapidapi.com")
$query = "як створити бота discord"
$response = Invoke-RestMethod "https://google-search72.p.rapidapi.com/search?q=$query%20gitgub&gl=us&lr=lang_ru&num=20&start=0" -Method GET -Headers $headers
$response.items | Select-Object title,snippet,displayLink,link | Format-List
````
### IMDb

https://rapidapi.com/apidojo/api/imdb8
```PowerShell
$key = "<TOKEN_API>" # 500 запитів на місяць
$query="Break"
$headers=@{}
$headers.Add("X-RapidAPI-Key", "$key")
$headers.Add("X-RapidAPI-Host", "imdb8.p.rapidapi.com")
$response = Invoke-RestMethod "https://imdb8.p.rapidapi.com/title/find?q=$query" -Method GET -Headers $headers
$response.results | select title,titletype,year,runningTimeInMinutes,id | Format-Table
"https://www.imdb.com$($response.results.id[0])"
$response.results.principals # актори
$response.results.image
````
### MoviesDatabase

https://rapidapi.com/SAdrian/api/moviesdatabase
```PowerShell
$key = "<TOKEN_API>"
$imdb_id = "tt0455275"
$headers=@{}
$headers.Add("X-RapidAPI-Key", "$key")
$headers.Add("X-RapidAPI-Host", "moviesdatabase.p.rapidapi.com")
$response = Invoke-RestMethod "https://moviesdatabase.p.rapidapi.com/titles/$imdb_id" -Method GET -Headers $headers
$response.results
````
#TMDB

https://developer.themoviedb.org/reference/intro/getting-started
```PowerShell
$TOKEN = "548e444e7812575caa0a7eXXXXXXXXXX"
$Endpoint = "search/tv" # пошук серіалу (tv) та фільму (movie) за назвою
$Query = "зимородок"
$url = $("https://api.themoviedb.org/3/$Endpoint"+"?api_key=$TOKEN&query=$Query")
$(Invoke-RestMethod -Uri $url -Method Get).results
$id = $(Invoke-RestMethod -Uri $url -Method Get).results.id # забрати id серіалу (210865) https://www.themoviedb.org/tv/210865

$Endpoint = "tv/$id" # отримання інформації про серіал за його ID
$url = $("https://api.themoviedb.org/3/$Endpoint"+"?api_key=$TOKEN")
$(Invoke-RestMethod -Uri $url -Method Get) # список сезонів (.seasons), кількість епізодів (.seasons.episode_count)

(Invoke-RestMethod -Uri "https://api.themoviedb.org/3/tv/$id/season/2?api_key=$Token" -Method Get).episodes # вивести 2 сезон
Invoke-RestMethod -Uri "https://api.themoviedb.org/3/tv/$id/season/2/episode/8?api_key=$Token" -Method Get # вивести 8 епізод
````
# ivi

https://ask.ivi.ru/knowledge-bases/10/articles/51697-dokumentatsiya-dlya-api-ivi

`Invoke-RestMethod https://api.ivi.ru/mobileapi/categories` список категорій та жанрів (genres/meta_genres) \
`Invoke-RestMethod https://api.ivi.ru/mobileapi/collections` вибірки

`(Invoke-RestMethod "https://api.ivi.ru/mobileapi/search/v7/?query=zimorodok").result.seasons.number` у сезонів \
`(Invoke-RestMethod "https://api.ivi.ru/mobileapi/search/v7/?query=zimorodok").result.seasons[1].episode_count` у серій у другому сезоні \
`(Invoke-RestMethod "https://api.ivi.ru/mobileapi/search/v7/?query=zimorodok").result.seasons[1].ivi_release_info.date_interval_min` дата виходу наступної серії \
`(Invoke-RestMethod "https://api.ivi.ru/mobileapi/search/v7/?query=zimorodok").result.kp_rating` рейтинг у Кінопошук (8.04)

`$id = (Invoke-RestMethod "https://api.ivi.ru/mobileapi/search/v7/?query=zimorodok").result.kp_id` отримати id до Кінопошуку (5106881) \
`id=$(curl -s https://api.ivi.ru/mobileapi/search/v7/?query=zimorodok | jq .result[].kp_id)` отримати id до Кінопошуку

# Kinopoisk
``` Bash
id=5106881
get=$(curl -s https://www.kinopoisk.ru/film/$id/episodes/)
printf "%s\n" "${get[@]}" | grep-A 1 "Сезон 2" | grep "епізодів" | sed -r "s/^.+\: //" # кількість епіздовід у другому сезоні (8)
````
### kinopoisk.dev

https://t.me/kinopoiskdev_bot - отримати токен \
https://kinopoisk.dev/documentation - документація з API у форматі OpenAPI

`GET /v1.4/movie/{id}` пошук по id
```PowerShell
$id = 5106881
$API_KEY = "ZYMNJJA-0J8MNPN-PB4N7R7-XXXXXXX"

$Header = @{
"accept" = "application/json"
"X-API-KEY" = "$API_KEY"
}
$irm = Invoke-RestMethod "https://api.kinopoisk.dev/v1.4/movie/$id" -Method GET -Headers $Header
$irm.rating.kp # рейтинг у Кінопошук (8,079)
$irm.seasonsInfo # кількість сезонів та епізодів у них
````
``` Bash
id=5106881
API_KEY="ZYMNJJA-0J8MNPN-PB4N7R7-XXXXXXX"
get=$(curl -s -X GET \
"https://api.kinopoisk.dev/v1.4/movie/$id" \
-H "accept: application/json" \
-H "X-API-KEY: $API_KEY")
echo $get | jq .rating.kp # рейтинг у Кінопошук (8,079)
echo $get | jq .seasonsInfo[1].episodesCount # кількість епізодів у другому [1] сезоні (6)
````
`GET /v1.4/movie/search`
``` Bash
query="zimorodok"
page=1 # кількість сторінок для вибірки
limit=1 # кількість елементів на сторінці
curl -s -X GET \
"https://api.kinopoisk.dev/v1.4/movie/search?page=$page&limit=$limit&query=$query" \
-H "accept: application/json" \
-H "X-API-KEY: $API_KEY" | jq.

limit=5
request = $ (curl -s -X GET \
"https://api.kinopoisk.dev/v1.4/movie/search?page=$page&limit=$limit&query=%D0%B7%D0%B8%D0%BC%D0%BE%D1%80%D0% BE%D0%B4%D0%BE%D0%BA" \
-H "accept: application/json" \
-H "X-API-KEY: $API_KEY" | jq.)
echo $request | jq '.docs[] | select(.year == 2022)' # відфільтрувати висновок за роком виходу
````
```PowerShell
$API_KEY = "ZYMNJJA-0J8MNPN-PB4N7R7-XXXXXXX"
$page = 1
$limit = 5
$query = "%D0%B7%D0%B8%D0%BC%D0%BE%D1%80%D0%BE%D0%B4%D0%BE%D0%BA"
$request = Invoke-RestMethod -Uri "https://api.kinopoisk.dev/v1.4/movie/search?page=$page&limit=$limit&query=$query" -Headers @{"accept"="application/json "; "X-API-KEY"="$API_KEY"}
$request.docs | Where-Object year -eq 2022
````
### UrlCode
```PowerShell
function Get-PercentEncode ($str) {
$bytes = [System.Text.Encoding]::UTF8.GetBytes($str)
($bytes | ForEach-Object { "{0:X2}" -f $_ }) -join '%' -replace "^","%"
}
Get-PercentEncode "зимородок"
````
```PowerShell
function Get-UrlEncode($str) {
[System.Web.HttpUtility]::UrlEncode($str)
}
UrlEncode "зимородок"
````
``` Bash
percent-encode() {
	str=$1
echo -n "$1" | iconv -t utf8 | od-An-tx1 | tr ''% | tr -d '\n'
}
percent-encode "зимородок"
````
```PowerShell
function Get-UrlDecode($encoded) {
[System.Uri]::UnescapeDataString($encoded)
}
Get-UrlDecode "%D0%B7%D0%B8%D0%BC%D0%BE%D1%80%D0%BE%D0%B4%D0%BE%D0%BA"
````
``` Bash
percent-decode() {
encoded=$1
local url_encoded="${1//+/ }"
printf '%b' "${url_encoded//%/\x}"
}
%-decode "%D0%B7%D0%B8%D0%BC%D0%BE%D1%80%D0%BE%D0%B4%D0%BE%D0%BA"
````
# VideoCDN

https://github.com/notssh/videocdn-api \
https://github.com/API-Movies/videocdn \
https://api-movies.github.io/videocdn/index.json
```PowerShell
$kp_id = 5106881
$token = "YfTWH2p3Mai7ziqDoGjS3yXXXXXXXXXX"
$ep = "tv-series"
$(Invoke-RestMethod $("https://videocdn.tv/api/$ep"+"?api_token=$token&field=kinopoisk_id&query=$kp_id")).data.episodes | Where-Object season_num -eq 2 | Select-Object @{Name="Episode"; Expression={$_.num}}, @{Name="Voice"; Expression={$_.media.translation.title}} # відфільтрувати серії по другому сезону та відобразити всі озвучки до серій
````
``` Bash
kp_id=5106881
token="YfTWH2p3Mai7ziqDoGjS3yXXXXXXXXXX"
ep="tv-series"
curl -s "https://videocdn.tv/api/$ep?api_token=$token&field=kinopoisk_id&query=$kp_id" | jq ".data[].episodes | length" # кількість серій
curl -s "https://videocdn.tv/api/$ep?api_token=$token&field=kinopoisk_id&query=$kp_id" | jq ".data[].episodes[] | select(.season_num == 2) | {episode: .ru_title, voice: .media[].translation.title}" # відфільтрувати параметри виводу
````
# Telegram

@BotFather (https://t.me/BotFather) /newbot

https://api.telegram.org/bot<token>/<endpoint>

https://core.telegram.org/bots/api#getupdates
```PowerShell
function Get-FromTelegram {
param (
$Token = "687...:AAF...",
[switch]$Date,
[switch]$Last,
[switch]$ChatID
)
$endpoint = "getUpdates"
$url = "https://api.telegram.org/bot$Token/$endpoint"
$result = Invoke-RestMethod -Uri $url
if ($Date) {
$Collections = New-Object System.Collections.Generic.List[System.Object]
foreach ($r in $($result.result)) {
$EpochTime = [DateTime]"1/1/1970"
$TimeZone = Get-TimeZone
$UTCTime = $EpochTime.AddSeconds($r.message.date)
$d = $UTCTime.AddMinutes($TimeZone.BaseUtcOffset.TotalMinutes)
$Collections.Add([PSCustomObject]@{
Message = $r.message.text;
Date = $d
})
}
$Collections
}
else {
if ($Last) {
$result.result.message.text[-1]
}
elseif ($ChatID) {
$Collections = New-Object System.Collections.Generic.List[System.Object]
foreach ($r in $($result.result)) {
$Collections.Add([PSCustomObject]@{
Message = $r.message.text;
UserName = $r.message.chat.username;
ChatID = $ r.message.chat.id;
ChatType = $r.message.chat.type
})
}
$Collections
}
else {
$result.result.message.text
}
}
}
````
`Get-FromTelegram` \
`Get-FromTelegram-Last` \
`Get-FromTelegram -Date` \
`Get-FromTelegram-ChatID`

https://core.telegram.org/bots/api#sendmessage
```PowerShell
function Send-ToTelegram {
param (
[Parameter(Mandatory = $True)]$Text,
$Token = "687...:AAF...",
$Chat = "125468108",
$Keyboard
)
$endpoint = "sendMessage"
$url = "https://api.telegram.org/bot$Token/$endpoint"
$Body = @{
chat_id = $Chat
text = $Text
}
if ($keyboard -ne $null) {
$Body += @{reply_markup = $keyboard}
}
Invoke-RestMethod -Uri $url -Body $Body
}
````
`Send-ToTelegram -Text "Send test from powershell"`
```PowerShell
$LastDate = (Get-FromTelegram -date)[-1].
while ($ true) {
$LastMessage = (Get-FromTelegram -date)[-1]
Start-Sleep 1
$LastDateTest = $LastMessage.Date
if (($LastMessage.Message -match "/Service") -and ($LastDate -ne $LastDateTest)) {
$ServiceName = $($LastMessage.Message -split " ")[-1]
$Result = $(Get-Service $ServiceName -ErrorAction Ignore).Status
if ($Result) {
Send-ToTelegram -Text $Result
} else {
Send-ToTelegram -Text "Service not found"
}
$LastDate = $LastDateTest
}
}
````
`/Service vpnagent` \
`/Service WinRM` \
`/Service test`

### Button
```PowerShell
$keyboard = '{
"inline_keyboard":[[
{"text":"Uptime","callback_data":"/Uptime"},
{"text":"Test","callback_data":"/Test"}
]]
}'
Send-ToTelegram -Тест "Test buttons" -Keyboard $keyboard
$request = (Invoke-RestMethod -Uri "https://api.telegram.org/bot$Token/getUpdates").result.callback_query
$request.data # прочитати callback_data натиснутою кнопки
$request.message.date
````
# Discord

https://discord.com/developers/applications

Створюємо Applications (General Information). У Bot прив'язуємо до Application та копіюємо токен авторизації. У OAuth2 - URL Generator вибираємо bot і права Administrator і копіюємо створений URL додавання на канал. Переходимо по URL і додаємо бота на сервер. Отримуємо ID каналу на сервері (текстові канали правою кнопкою миші копіюємо посилання і забираємо останній id в url).

### Send to Discord
``` Bash
DISCORD_TOKEN="MTE5NzE1NjM0NTM3NjQxMTcyOQ.XXXXXX.EzBF6RA9Kx_MSuhLW5elH1U-XXXXXXXXXXXXXX"
DISCORD_CHANNEL_ID="119403124XXXXXXXXXX"
TEXT=" Test від Bash "
URL="https://discordapp.com/api/channels/$DISCORD_CHANNEL_ID/messages"
curl -s -X POST $URL \
-H "Authorization: Bot $DISCORD_TOKEN" \
-H "Content-Type: application/json" \
-d "{\"content\": \"$TEXT\"}"
````
```PowerShell
$DISCORD_TOKEN = "MTE5NzE1NjM0NTM3NjQxMTcyOQ.XXXXXX.EzBF6RA9Kx_MSuhLW5elH1U-XXXXXXXXXXXXXX"
$DISCORD_CHANNEL_ID = "119403124XXXXXXXXXX"
$TEXT = " Test from PowerShell "
$URL = "https://discordapp.com/api/channels/$DISCORD_CHANNEL_ID/messages"
$Body = @{
content = $TEXT
} | ConvertTo-Json
curl -s $URL -X POST -H "Authorization: Bot $DISCORD_TOKEN" -H "Content-Type: application/json" -d $Body
````
### Read from Discord
``` Bash
curl -s -X GET $URL \
-H "Authorization: Bot $DISCORD_TOKEN" \
-H "Content-Type: application/json" | jq -r .[0].
````
```PowerShell
$messages = (curl -s -X GET $URL -H "Authorization: Bot $DISCORD_TOKEN" -H "Content-Type: application/json" | ConvertFrom-Json)
$messages | Select-Object content,timestamp,{$_.author.username}
````
### HttpClient
```PowerShell
$DISCORD_TOKEN = "MTE5NzE1NjM0NTM3NjQxMTcyOQ.XXXXXX.EzBF6RA9Kx_MSuhLW5elH1U-XXXXXXXXXXXXXX"
$DISCORD_CHANNEL_ID = "119403124XXXXXXXXXX"
$URL = "https://discordapp.com/api/channels/$DISCORD_CHANNEL_ID/messages"
$HttpClient = New-Object System.Net.Http.HttpClient
$HttpClient.DefaultRequestHeaders.Authorization = "Bot $DISCORD_TOKEN"
$response = $HttpClient.GetAsync($URL).Result
$messages = $response.Content.ReadAsStringAsync().Result
($messages | ConvertFrom-Json).content
````
### Button
``` Bash
curl -X POST $URL \
-H "Content-Type: application/json" \
-H "Authorization: Bot $DISCORD_TOKEN" \
-d'
{
"content": "Test text for button",
"components": [
{
"type": 1,
"components": [
{
"type": 2,
"label": "Button",
"style": 1,
"custom_id": "button_click"
}
]
}
]
}'
````
### Discord.Net.Webhook
```PowerShell
Add-Type -Path $(ls "$home\Documents\Discord.NET\*.dll").FullName
# https://discordapp.com/api/webhooks/<webhook_id>/<webhook_token> (Налаштувати канал - Інтеграція)
$webhookId = 11975772800000000000
$webhookToken = "rs8AA-XXXXXXXXXXX_Vk5RUI4A6HuSGhpCCTepq25duwCwLXasfv6u23a7XXXXXXXXXX"
$messageContent = "Test dotNET"
$client = New-Object Discord.Webhook.DiscordWebhookClient($webhookId, $webhookToken)
$client.SendMessageAsync($messageContent).Wait()
````
### Discord.Net.WebSocket
```PowerShell
$DiscordAssemblies = $(ls "$home\Documents\Discord.NET\*.dll").FullName
foreach ($assembly in $DiscordAssemblies) {
Add-Type -Path $assembly
}
$DISCORD_TOKEN = "MTE5NzE1NjM0NTM3NjQxMTcyOQ.XXXXXX.EzBF6RA9Kx_MSuhLW5elH1U-XXXXXXXXXXXXXX"
$Client = New-Object Discord.WebSocket.DiscordSocketClient
$Client.Add_MessageReceived({
param($message)
if ($message.Author.Id -ne $Client.CurrentUser.Id) {
Write-Host ("Received message from " + $message.Author.Username + ": " + $message.Content)
if ($message.Content.Contains("ping")) {
$message.Channel.SendMessageAsync("pong").GetAwaiter().GetResult()
}
}
})
$Client.LoginAsync([Discord.TokenType]::Bot, $DISCORD_TOKEN).GetAwaiter().GetResult()
#$Client.StartAsync().Wait()
$Client.StartAsync().GetAwaiter().GetResult()
$Client.ConnectionState

[console]::ReadKey($true)
$Client.LogoutAsync().GetAwaiter().GetResult()
$Client.Dispose()
````
# oh-my-posh

[Install](https://ohmyposh.dev/docs/installation/windows)

`winget install JanDeDobbeleer.OhMyPosh -s winget` \
`choco install oh-my-posh -y` \
`scoop install https://github.com/JanDeDobbeleer/oh-my-posh/releases/latest/download/oh-my-posh.json` \
`Set-ExecutionPolicy Bypass-Scope Process-Force; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://ohmyposh.dev/install.ps1'))`

[Themes](https://ohmyposh.dev/docs/themes)

`Get-PoshThemes` \
`oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH/di4am0nd.omp.json" | Invoke-Expression`\
`oh-my-posh init pwsh --config "https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/main/themes/cert.omp.json" | Invoke-Expression`

`New-Item -Path $PROFILE -Type File -Force` \
`notepad $PROFILE` \
`oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH/di4am0nd.omp.json" | Invoke-Expression`

### themes-performance
```PowerShell
Install-Module themes-performance -Repository NuGet
Import-Module themes-performance
Set-PoshTheme -Theme System-Sensors # -Save
Set-PoshTheme -Theme System-Performance # -Save
Set-PoshTheme -Theme Pwsh-Process-Performance # -Save
````
### Terminal-Icons

`Install-Module -Name Terminal-Icons -Repository PSGallery` \
`scoop bucket add extras` \
`scoop install terminal-icons`

`notepad $PROFILE` \
`Import-Module -Name Terminal-Icons`

Використовує шрифти, які потрібно встановити та налаштувати у параметрах профілю PowerShell: [Nerd Fonts](https://github.com/ryanoasis/nerd-fonts) \
Список шрифтів: https://www.nerdfonts.com/font-downloads \
Завантажити та встановити шрифт схожий на Cascadia Code - [CaskaydiaCove](https://github.com/ryanoasis/nerd-fonts/releases/download/v3.1.1/CascadiaCode.zip)

# Pester

Source: [Pester](https://github.com/pester/Pester)

`Install-Module -Name Pester -Repository PSGallery -Force -AllowClobber` \
`Import-Module Pester` \
`$(Get-Module Pester -ListAvailable).Version`

`.Tests.ps1`
```PowerShell
function Add-Numbers {
param (
[int]$a,
[int]$b
)
$a + $b
}
Describe "Add-Numbers" {
Context "При додаванні двох чисел" {
It "Має повернутися правильна сума" {
$result = Add-Numbers -a 3 -b 4
$result | Should -Be 7
}
}
Context "При додаванні двох чисел" {
It "Має повернутися помилка (5+0 -ne 4)" {
$result = Add-Numbers -a 5 -b 0
$result | Should -Be 4
}
}
}

function Get-RunningProcess {
return Get-Process | Select-Object -ExpandProperty Name
}
Describe "Get-RunningProcess" {
Context "За наявності запущених процесів" {
"Повинен повертати список імен процесів" {
$result = Get-RunningProcess
$result | Should -Contain "svchost"
$result | Should -Contain "explorer"
}
}
Context "Коли немає запущених процесів" {
"Повинен повертати порожній список" {
# Замокати функцію Get-Process, щоб вона завжди повертала порожній список процесів
Mock Get-Process { return @() }
$result = Get-RunningProcess
$result | Should -BeEmpty
}
}
}
````
