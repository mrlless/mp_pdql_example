**ОБЩИЕ ЗАПРОСЫ ПО АКТИВАМ.**

**Список Windows-активов за исключением тех, что в фильтре:**

select(@WindowsHost, WindowsHost.OsName, WindowsHost.@CreationTime,
WindowsHost.@AuditTime, WindowsHost.@PentestTime) \|
group(WindowsHost.OsName) \| filter(windowsHost.osname not in
\[\'Windows 10\', \'Windows 8\', \'Windows 8.1\', \'Windows 2016\',
\'Windows 2019\', \'Windows 2012\', \'Windows 2012 R2\'\])

**Найти Windows АРМ:**

filter(WindowsHost.HostType = \'Desktop\') \| select(@Host, Host.OsName,
Host.@CreationTime, Host.@UpdateTime) \| sort(@Host ASC)

АРМ_WIN без аудита

WindowsHost.HostType = \'Desktop\' and Host.@Audittime = null

Host.HostType=\'server\' and Host.OsName not like \'Windows%\' and
Host.@Audittime = null

**Найти активы, одновременно имеющие роль DNS Server и Domain
Controller:**

filter(Host.HostRoles.Role = \'DNS Server\' AND Host.HostRoles.Role
=\'Domain Controller\') \| select(@Host, Host.OsName,
Host.@CreationTime, Host.@UpdateTime) \| sort(@Host ASC)

**Список родительских и дочерних PID:**

select(@Computer, Computer.Processes.Name, Computer.Processes.PID,
Computer.Processes.ParentPID) \| filter(Computer.Processes.Name and
Computer.Processes.PID and Computer.Processes.ParentPID) \|
join(Select(@Computer, Computer.Processes.Name, Computer.Processes.PID)
\| filter (Computer.Processes.Name and Computer.Processes.PID) as P,
\@Computer = P.@Computer and Computer.Processes.ParentPID =
P.Computer.Processes.PID) \| select(@Computer, Computer.Processes.Name
as child_proc, P.Computer.Processes.Name as parent_proc) \|
sort(child_proc DESC)

**Соотнести все виртуальные машины с их гипервизорами:**

select(@ESXiHost, ESXiHost.Hypervisors.VMs.ID) \|
filter(ESXiHost.Hypervisors.VMs.ID) \| join(select(@Host, Host.VmId) as
Q, ESXiHost.Hypervisors.VMs.ID = Q.Host.VmId)

**Список подобранных УЗ на активах с помощью профиля Bruteforce
PenTest:**

select(@Host, Host.OsName, Host.@CreationTime, Host.@UpdateTime,
Host.Endpoints\<TransportEndpoint\>.Service.Checks\<RemoteAccessAccountBruteforce\>.Login
as login,
Host.Endpoints\<TransportEndpoint\>.Service.Checks\<RemoteAccessAccountBruteforce\>.Password
as password) \| filter(Login or password)

**Список подобранных определенных УЗ на активах с помощью профиля
Bruteforce PenTest:**

select(@Host, Host.OsName, Host.@CreationTime, Host.@UpdateTime,
Host.Endpoints\<TransportEndpoint\>.Service.Checks\<RemoteAccessAccountBruteforce\>.Login,
Host.Endpoints\<TransportEndpoint\>.Service.Checks\<RemoteAccessAccountBruteforce\>.Password)
\|
filter((Host.Endpoints\<TransportEndpoint\>.Service.Checks\<RemoteAccessAccountBruteforce\>.Login
like \'%%\') OR
(Host.Endpoints\<TransportEndpoint\>.Service.Checks\<RemoteAccessAccountBruteforce\>.PAssword
like \'%%\'))

**Список активов с ПО:**

filter(host.softs) \| select(@Host, Host.OsName)

**Список активов без ПО:**

filter(not host.softs) \| select(@Host, Host.OsName)

**Поиск определенного ПО на активах:**

filter(Host.Softs contains \"TeamViewer 15.6.7\") \| select(@Host,
Host.OsName, Host.@CreationTime, Host.@UpdateTime) \| sort(@Host ASC)

примеры других фильтров:

Host.Softs intersect \[\"TeamViewer 15.6.7\", \"Tor Browser 5.0.3\"\]

Host.Softs.Name in \[\"TeamViewer 15.6.7\", \"Tor Browser 5.0.3\"\]

Host.Softs.Name = \"TeamViewer\"

Host.Softs.Name like \"TeamView%\"

**Поиск расшаренных папок на активах:**

select(@Host, Host.Endpoints\<SmbShare\>.Name as share_name,
Host.Endpoints\<SmbShare\>.LocalPath) \| filter(share_name) \|
group(share_name, COUNT(\*)) \| sort(\"COUNT(\*)\" DESC)

**Разрабочтик ПО нерезидент РФ:**

filter(Host.Softs.Vendor not in \[\"Communigate Systems\",
\"Crypto-Pro\", \"Doctor Web\", \"Famatech\", \"Igor Pavlov\",
\"InfoTeCS\", \"Kaspersky Lab\", \"Positive Technologies\", \"QIP\",
\"Ruby Team\", \"Veeam Software\", \"Yandex\",\"CherryPy\", \"Dnsmasq\",
\"EZB Systems\", \"Eclipse Foundation\", \"Go\", \"Gpg4win\", \"ISC\",
\"KeePass\", \"Lighttpd\", \"MariaDB Foundation\", \"Media Player
Classic\", \"Notepad++\", \"Nullsoft\", \"OpenSSH\", \"OpenSSL
Project\", \"OpenSSL Software Foundation\", \"OpenVPN\", \"PHP Group\",
\"Pidgin\", \"PostgreSQL\", \"PowerDns\", \"ProFTPD Project\",
\"PuTTy\", \"Python Software Foundation\", \"Realtek\", \"Redis\",
\"Samba\", \"Sendmail\", \"Squid\", \"SumatraPDF\", \"Telegram\", \"Tor
Project\", \"TortoiseSVN\", \"Total Commander\", \"TrueCrypt
Foundation\", \"University Of Cambridge\", \"VideoLAN\", \"WhatsApp\",
\"WinPcap\", \"Wireshark\", \"XnView\", \"mod_ssl\",\"vsFTPd\"\]) \|
select(@Host, Host.OsName, Host.@CreationTime, Host.@UpdateTime) \|
sort(@Host ASC)

**Поиск пользователей на активах:**

select(@Host, Host.OsName, Host.@CreationTime, Host.@UpdateTime,
Host.User.Name) \| sort(Host.User.Name DESC)

**Не влияет на важные бизнес-процессы компании (НЕ на активах высокой
значимости):**

filter(Host.@Importance != \'H\') \| select(@Host, Host.OsName,
Host.@CreationTime, Host.@UpdateTime) \| sort(@Host ASC)

**Список активов, обновленных ранее даты в фильтре:**

select(@Host, Host.OsName, Host.@CreationTime, Host.@UpdateTime) \|
sort(@Host ASC) \| filter(host.@UpdateTime \< 2019-10-01)

**Список групп пользователей на узлах c операционной системой семейства
Unix**

**и информация о пользователях, состоящих в них:**

Select(@UnixHost, UnixHost.Groups.Name, UnixHost.Groups.Users) \|
Join(Select(@UnixHost, UnixHost.User.ID, UnixHost.User.Name) as U,
\@UnixHost = U.@UnixHost and UnixHost.Groups.Users =
U.UnixHost.User.Name) \| Select (@UnixHost, UnixHost.Groups.Name,
U.UnixHost.User.ID, UnixHost.Groups.Users)

**Список ПО, которое не поддерживается в системе:**

Select(Host.Softs.Name as name, Host.Softs.Version as version,
Host.Softs.Vendor as vendor, Host.Softs.@Type as t) \| Filter(t =
\'Software\') \| select (name, version, vendor) \| Unique()

**Список активов, которые устареют в течение недели:**

Select(@Host,Host.@DeletionTime) \| Filter (Host.@DeletionTime \<=
Now() + 7days)

**Список доменных пользователей, которые могут заходить по RDP на
машины:**

select(@WindowsHost,
WindowsHost.Privileges.seRemoteInteractiveLogonRight) \|
join(Select(@WindowsHost, WindowsHost.Groups.SID) as Q, \@WindowsHost =
Q.@WindowsHost and WindowsHost.Privileges.seRemoteInteractiveLogonRight
= Q.WindowsHost.Groups.SID) \| filter(Q.WindowsHost.Groups.SID) \|
join(select(@ActiveDirectory, ActiveDirectory.Domains.Name,
ActiveDirectory.Domains.Groups.ObjectSid,
ActiveDirectory.Domains.Groups.AllMembers.ObjectSid,
ActiveDirectory.Domains.Groups.AllMembers.CN,
ActiveDirectory.Domains.Groups.AllMembers.ObjectType) \|
filter(ActiveDirectory.Domains.Groups.ObjectSid) as q2,
WindowsHost.Privileges.seRemoteInteractiveLogonRight =
q2.ActiveDirectory.Domains.Groups.ObjectSid) \|
select(q2.ActiveDirectory.Domains.Groups.AllMembers.CN,
q2.ActiveDirectory.Domains.Groups.AllMembers.ObjectType,
q2.ActiveDirectory.Domains.Name,
q2.ActiveDirectory.Domains.Groups.AllMembers.ObjectSid,
COMPACT(@WindowsHost))

**ПОИСК УЯЗВИМОСТЕЙ НА АКТИВАХ**

**Найти Windows-активы, на которых не установлена KB982018:**

filter(not (WindowsHost.Updates.UpdateId = \"KB982018\") and
WindowsHost.Updates.UpdateId) \| select(@Host, Host.OsName,
Host.@CreationTime, Host.@UpdateTime) \| sort(@Host ASC)

**Поиск по всем уязвимостям на активах:**

select(@Host, Host.@Vulners, Host.@Vulners.DiscoveryTime,
Host.@Vulners.Status, Host.@Vulners.FixType, Host.@Vulners.IsDanger,
Host.@Vulners.Tags) \| filter(Host.@Vulners)

**Вывести только уязвимости ОС:**

select(@Host, Host.OsName, Host.OsVersion, Host.@NodeVulners) \|
filter(Host.@Vulners)

**Список файловых служб на операционных системах, отличных от Windows
7:**

filter(Host\[HostRoles.Role = \'File Service\' and OsCandidates.Family =
\'Windows\' and OsName != \'Windows 7\'\]) \| select(@Host, Host.OsName,
Host.@CreationTime, Host.@UpdateTime) \| sort(@Host ASC)

**РАБОТА С УЗ И ГРУППАМИ В WINDOWS-АКТИВАХ.**

**Найти УЗ пользователей, у которых сменился пароль в течение последнего
месяца, на активах с ОС Windows:**

select(WindowsHost.User\<WindowsUser\>.Name,
WindowsHost.User\<WindowsUser\>.PasswordLastChanged as t) \| filter(t \>
Now() - 31D)

**Список участников группы Администраторы домена:**

select(@DirectoryService as Domain, DirectoryService.Domains.Groups.CN
as \"Group\",directoryService.Domains.Groups.objectsid as sid,
DirectoryService.Domains.Groups.AllMembers.UserPrincipalName as UPN) \|
filter(sid like \"%-512\")

**Список участников группы Администраторы домена в таблицу из колонок:
название домена и UPN:**

select(@DirectoryService as Domain, DirectoryService.Domains.Groups.CN
as \"Group\",
DirectoryService.Domains.Groups.AllMembers.UserPrincipalName as UPN) \|
filter(\"Group\" = \'Администраторы домена\') \| select(Domain, UPN)

**Список всех УЗ домена с информацией о времени создания УЗ, дате
последнего входа, параметрах пароля, членства в группах и т.п.:**

[select(@ActiveDirectory, ActiveDirectory.Domains.Users.CN,
ActiveDirectory.Domains.Users.UserPrincipalName,
ActiveDirectory.Domains.Users.DistinguishedName,
ActiveDirectory.Domains.Users.WhenCreated,
ActiveDirectory.Domains.Users.LastLogonTimestamp,
ActiveDirectory.Domains.Users.AccountExpires,
ActiveDirectory.Domains.Users.PwdLastSet](about:blank),
ActiveDirectory.Domains.Users.AdminCount,
ActiveDirectory.Domains.Users.UserAccountControl.AccountDisable,
ActiveDirectory.Domains.Users.UserAccountControl.Lockout,
ActiveDirectory.Domains.Users.UserAccountControl.DontExpirePasswd,
ActiveDirectory.Domains.Users.UserAccountControl.PasswordExpired,
ActiveDirectory.Domains.Users.AllParents.CN)

**Список AD групп и ее участников:**

select(@DirectoryService as Domain, DirectoryService.Domains.Groups.CN
as \"Group\",
DirectoryService.Domains.Groups.AllMembers.UserPrincipalName as UPN)

**Список доменных УЗ с их дескрипторами безопасности:**

[select(ActiveDirectory.Domains.Users.samaccountname as name,
ActiveDirectory.domains.users.ObjectGuid as guid)](about:blank)

**Компьютеры в группе:**

select(DirectoryService.Domains.Groups,
DirectoryService.Domains.Groups.AllMembers) \| filter
(DirectoryService.Domains.Groups like \"Контроллеры домена%\" and
DirectoryService.Domains.Groups.AllMembers)

**Количество записей в группе:**

select(@DirectoryService, DirectoryService.Domains.Groups.CanonicalName,
DirectoryService.Domains.Groups.GroupType,
COMPACTUNIQUE(DirectoryService.Domains.Groups.DirectMembers.CN))

**Показывает установленный софт и версии на компьютерах определенной
группы АД**

select(DirectoryService.Domains.Groups,
DirectoryService.Domains.Groups.AllMembers) \|
filter(DirectoryService.Domains.Groups.AllMembers and
DirectoryService.Domains.Groups like \"GroupName\" \| join(select (@Host
as H, Host.Hostname as HN, Host.softs as SN, Host.softs.version as SV)
as Q, DirectoryService.Domains.Groups.AllMembers = Q.HN)

**Список УЗ пользователей, у которых сменился пароль в течение
последнего месяца, на активах с ОС Windows:**

[select(WindowsHost.User\<WindowsUser\>.Name,
WindowsHost.User\<WindowsUser\>.PasswordLastChanged as t) \| filter(t \>
Now() - 30D)](about:blank))

**Вывести только уязвимости ПО:**

select(@Host, Host.Softs.Name, Host.Softs.Version,
Host.Softs.@NodeVulners) \|
filter([[Host.Softs.@NodeVulners]{.underline}](about:blank))

**Вывести только уязвимости Linux пакетов:**

select(@UnixHost, UnixHost.Packages.Name, UnixHost.Packages.Version,
UnixHost.Packages.@NodeVulners) \|
filter([[UnixHost.Packages.@NodeVulners]{.underline}](about:blank))

**Вывести только уязвимости сетевых служб:**

select(@Host,
Host.Endpoints\<TransportEndpoint\>.Port,Host.Endpoints\<TransportEndpoint\>.@Vulners)
\| filter(Host.Endpoints\<TransportEndpoint\>.@Vulners)

**Активы с уязвимостями типа \"Удаленное выполнение кода\":**

select(@Host, Host.Softs.@Vulners, Host.Softs.@Vulners.DiscoveryTime,
Host.Softs.@Vulners.Status, Host.Softs.@Vulners.FixType,
Host.Softs.@Vulners.IsDanger, Host.Softs.@Vulners.Tags,
Host.Softs.@Vulners.Name) \| filter(Host.Softs.@Vulners.Name like
\"%Remote Code Execution%\" or Host.Softs.@Vulners.Name like
\"%Удаленное%выполнение%\")

**Поиск заданной уязвимости по активам:**

filter(Host.@Vulners.CVEs contains \"CVE-2021-34527\") \| select(@Host,
Host.OsName, Host.@CreationTime, Host.@UpdateTime, Host.@Vulners.CVEs)
\| sort(@Host ASC)

**Поиск одной из уязвимостей (операнд intersect):**

filter(Host.@Vulners.CVEs intersect \[\"CVE-2021-34527\",
\"CVE-2021-34527\"\]) \| select(@Host, Host.OsName, Host.@CreationTime,
Host.@UpdateTime) \| sort(@Host ASC)

примеры других фильтров:

Host.@Vulners.CVEs.Item in \[\"CVE-2021-34527\", \"CVE-2021-34527\"\]

Host.@Vulners.CVEs.Item = \"CVE-2021-34527\"

Host.@Vulners.CVEs.Item like \"%2021-34527\"

**Поиск уязвимостей за определенный момент времени:**

qsearch(\"10.193.0.112\") \| timepoint(2022-08-15T00:15:00) \|
select(@Host, Host.@Vulners, Host.@Vulners.DiscoveryTime,
Host.@Vulners.Status) \| filter(Host.@Vulners) \| limit(0)

**Кол-во уязвимостей с разбивкой по неделям за последние 8 недель:**

timeseries(8w, 1w, endofweek()) \| select(@Host, Host.@Vulners,
Host.@Vulners.DiscoveryTime, Host.@Vulners.Status, Host.@Time) \|
filter(Host.@Vulners) \| limit(0) \| group(Host.@Time, count(\*)) \|
sort(Host.@Time DESC)

**Интегральная уязвимость активов за три периода времени:**

timepoint(now()-2w) \| select(@Host, host.@CumulativeVulnerability as
\"2w_ago\") \| join(timepoint(now()-1w) \| select(@Host,
host.@CumulativeVulnerability as \"1w_ago\") as Q, \@Host = Q.@Host) \|
join(select(@Host, host.@CumulativeVulnerability as \"now_date\") as Qq,
\@host = qq.@host) \| select(@Host, \"2w_ago\", Q.\"1w_ago\",
Qq.now_date) \| sort(Qq.now_date DESC)

**Поиск по паспортам уязвимостей:**

filter(VulnerPassport.Links.Item like \"%MS17-010%\" and
VulnerPassport.AffectedComponents.Name) \| select(@VulnerPassport,
COMPACT(VulnerPassport.CVEs))

**Отсутствует публичный эксплоит:**

filter(Host.Softs.@Vulners.Metrics.Exploitable = false) \| select(@Host,
Host.OsName, Host.@CreationTime, Host.@UpdateTime) \| sort(@Host ASC)

**Тип уязвимости не RCE, LPE, DoS:**

filter(not (Host.Softs.@Vulners.Name like \"%Remote Code Execution%\" or
Host.Softs.@Vulners.Name like \"%Удаленное%выполнение%\")) \|
select(@Host, Host.OsName, Host.@CreationTime, Host.@UpdateTime) \|
sort(@Host ASC)

filter(not (Host.Softs.@Vulners.Name like \"%Повышение%привилеги%\")) \|
select(@Host, Host.OsName, Host.@CreationTime, Host.@UpdateTime) \|
sort(@Host ASC)

filter(not (Host.Softs.@Vulners.Name like \"dos%\" or
Host.Softs.@Vulners.Name like \"%Отказ%в%обслуживании%\")) \|
select(@Host, Host.OsName, Host.@CreationTime, Host.@UpdateTime) \|
sort(@Host ASC)

**Поиск уязвимости CVSS 3.1 ≤ 7:**

filter(Host.Softs.@Vulners.CVSS3BaseScore \<= 7) \| select(@Host,
Host.OsName, Host.@CreationTime, Host.@UpdateTime) \| sort(@Host ASC)

**Вывести общее количество CVE**

select(@Host, Host.OsName, Host.@CreationTime, Host.@UpdateTime,
COUNTUNIQUE(Host.@Vulners)) \| sort(@Host ASC) \|
group(SUM(COUNTUNIQUE(Host.@Vulners)) as \"Кол-во CVE\")

**ЗАПРОСЫ СВЯЗАННЫЕ С ОБСЛУЖИВАНИЕМ СЕТИ.**

**Список активов с установленными VPN-клиентами:**

filter(Computer.NetworkCard\[Name like \'%TAP%\' or Name like \'%VPN%\'
or Name like \'%Tun%\'\]) \| select(@Host, Host.OsName,
Host.@CreationTime, Host.@UpdateTime) \| sort(@Host ASC)

**Список активов, у которых встречается srv1 в
Названии/Описании/IP-адресе/FQDN\'е:**

qsearch(\"qsearch(\"srv1\") \| select(@Host)\") \| select(@Host,
Host.OsName, Host.@CreationTime, Host.@UpdateTime) \| sort(@Host ASC)

**Список сетевого оборудования Cisco:**

filter(NetworkDeviceHost.Vendor = \'Cisco\') \| select(@Host,
Host.OsName, Host.@CreationTime, Host.@UpdateTime) \| sort(@Host ASC)

**Список сетевых устройств с выводом mac-адреса, таблицей mac-адресов и
таблицей vlan:**

select(@NetworkDeviceHost as
host,NetworkDeviceHost.MacAddressTable.MacAddress as
mac,NetworkDeviceHost.MacAddressTable.Vlan as
vlan,NetworkDeviceHost.MacAddressTable.ports as port)

**Список сетевого оборудования с ролью Switch и информацией о
назначенных vlan:**

filter(NetworkDeviceHost.HostRoles.Role = \'Switch\' and
NetworkDeviceHost.Vlans)\| select(@NetworkDeviceHost,
NetworkDeviceHost.OsName, NetworkDeviceHost.Vlans.Name as VlanName,
NetworkDeviceHost.Vlans.ID as VlanID)

**Подсчет активов по IP адресам, кроме localhost, которые были
обнаружены за последнее время:**

select(@Host, host.@IpAddresses as ip) \| filter(ip not in
\[127.0.0.1,::1\]) \| group(ip, COUNT(\*) as cnt) \| filter(cnt\>1) \|
sort(cnt DESC)

**Список активов с адресом не из локальной сети:**

select(@Host, host.IpAddress) \| filter(host.IpAddress and not
(host.IpAddress in 10.0.0.0/8 OR host.IpAddress in 172.16.0.0/12 OR
host.IpAddress in 192.168.0.0/16 OR host.IpAddress in 127.0.0.0/8 OR
host.IpAddress in 169.254.0.0/16)) \| sort(host.IpAddress ASC)

**Поиск актива по IP:**

filter(Host.@IpAddresses contains 192.168.1.1) \| select(@Host,
Host.OsName, Host.@CreationTime, Host.@UpdateTime) \| sort(@Host ASC)

примеры других фильтров:

Host.@IpAddresses intersect \[192.168.1.1, 192.168.1.2\]

Host.@IpAddresses.Item in \[192.168.1.0/24, 192.168.1.2\]

Host.@IpAddresses.Item = 192.168.1.1

**Найти активы, у которых \>= 2 активных сетевых интерфейсов:**

select(@Host, Host.Interfaces.Name as name, Host.Interfaces.IsEnabled as
enabled) \| filter(name != \"lo\" and name != \"Npcap Loopback Adapter\"
and name and enabled = true) \| group(@Host, COUNT(\*) as result) \|
filter(result \>= 2)

**Отфильтровать АРМ с \> 1 сетевыми интерфейсами:**

filter(not NetworkDeviceHost) \| select(@Host, Host.OsName,
Host.@CreationTime, Host.@UpdateTime) \| join(select(@Host,
Host.Interfaces.Name, Host.Interfaces.IsEnabled) \| filter
(Host.Interfaces.IsEnabled = True and Host.Interfaces.Name != null) \|
group(@Host, count(\*) as \"Interfaces\") as Q, \@Host = Q.@Host) \|
select(@Host, Host.OsName, Host.@CreationTime, Host.@UpdateTime,
Q.Interfaces) \| sort(Q.Interfaces DESC)

**СУБД ORACLE.**

**Пользователям разрешена аутентификация на уровне ОС:**

filter(Host.Softs\<OracleDBSoft\>) \| select(@Host,
Host.Softs\<OracleDBSoft\>.Databases.DBName,
Host.Softs\<OracleDBSoft\>.Databases.DBParameters.Name as ParameterName,
Host.Softs\<OracleDBSoft\>.Databases.DBParameters.Value as
ParameterValue) \| filter(ParameterName = \'remote_os_authent\' and
ParameterValue != \'False\') \| sort(@Host ASC)

**Префикс аутентификации пользователей:**

filter(Host.Softs\<OracleDBSoft\>) \| select(@Host,
Host.Softs\<OracleDBSoft\>.Databases.DBName,
Host.Softs\<OracleDBSoft\>.Databases.DBParameters.Name as ParameterName,
Host.Softs\<OracleDBSoft\>.Databases.DBParameters.Value as
ParameterValue) \| filter(ParameterName = \'OS_AUTHENT_PREFIX\' and
ParameterValue = \'ops\$\') \| sort(@Host ASC)

**Использование внешних групп для управления БД:**

filter(Host.Softs\<OracleDBSoft\>) \| select(@Host,
Host.Softs\<OracleDBSoft\>.Databases.DBName,
Host.Softs\<OracleDBSoft\>.Databases.DBParameters.Name as ParameterName,
Host.Softs\<OracleDBSoft\>.Databases.DBParameters.Value as
ParameterValue) \| filter(ParameterName = \'OS_ROLES\' and
ParameterValue != \'False\') \| sort(@Host ASC)

**Разрешена аутентификация с использованием файла паролей:**

filter(Host.Softs\<OracleDBSoft\>) \| select(@Host,
Host.Softs\<OracleDBSoft\>.Databases.DBName,
Host.Softs\<OracleDBSoft\>.Databases.DBParameters.Name as ParameterName,
Host.Softs\<OracleDBSoft\>.Databases.DBParameters.Value as
ParameterValue) \| filter(ParameterName = \'REMOTE_LOGIN_PASSWORDFILE\'
and ParameterValue != \'NONE\') \| sort(@Host ASC)

**Разрешено применять роли ОС удаленных пользователей:**

filter(Host.Softs\<OracleDBSoft\>) \| select(@Host,
Host.Softs\<OracleDBSoft\>.Databases.DBName,
Host.Softs\<OracleDBSoft\>.Databases.DBParameters.Name as ParameterName,
Host.Softs\<OracleDBSoft\>.Databases.DBParameters.Value as
ParameterValue) \| filter(ParameterName = \'REMOTE_OS_ROLES\' and
ParameterValue != \'False\') \| sort(@Host ASC)

**Нечувствительность пароля к регистру:**

filter(Host.Softs\<OracleDBSoft\>) \| select(@Host,
Host.Softs\<OracleDBSoft\>.Databases.DBName,
Host.Softs\<OracleDBSoft\>.Databases.DBParameters.Name as ParameterName,
Host.Softs\<OracleDBSoft\>.Databases.DBParameters.Value as
ParameterValue) \| filter(ParameterName = \'SEC_CASE_SENSITIVE_LOGON\'
and ParameterValue != \'True\') \| sort(@Host ASC)

**Защита подключения к серверному процессу базы данных не соответствует
требованиям:**

filter(Host.Softs\<OracleDBSoft\>) \| select(@Host,
Host.Softs\<OracleDBSoft\>.Databases.DBName,
Host.Softs\<OracleDBSoft\>.Databases.DBParameters.Name as ParameterName,
Host.Softs\<OracleDBSoft\>.Databases.DBParameters.Value as
ParameterValue) \| filter(ParameterName =
\'SEC_MAX_FAILED_LOGIN_ATTEMPTS\' and ParameterValue = \'UNLIMITED\') \|
sort(@Host ASC)

**Отсутствует проверка сложности пароля:**

filter(Host.Softs\<OracleDBSoft\>) \| select(@Host,
Host.Softs\<OracleDBSoft\>.Databases.DBName,
Host.Softs\<OracleDBSoft\>.Databases.Profiles.Name,
Host.Softs\<OracleDBSoft\>.Databases.Profiles.Parameters.PasswordVerifyFunction
as ParameterValue) \| filter(ParameterValue = \'\') \| sort(@Host ASC)

**Неограниченное число неудачных попыток входа:**

filter(Host.Softs\<OracleDBSoft\>) \| select(@Host,
Host.Softs\<OracleDBSoft\>.Databases.DBName,
Host.Softs\<OracleDBSoft\>.Databases.Profiles.Name,
Host.Softs\<OracleDBSoft\>.Databases.Profiles.Parameters.FailedLoginAttempts
as ParameterValue) \| filter(ParameterValue = -1) \| sort(@Host ASC)

**Срок истечения пароля проигнорирован:**

filter(Host.Softs\<OracleDBSoft\>) \| select(@Host,
Host.Softs\<OracleDBSoft\>.Databases.DBName,
Host.Softs\<OracleDBSoft\>.Databases.Profiles.Name,
Host.Softs\<OracleDBSoft\>.Databases.Profiles.Parameters.PasswordGraceTime
as ParameterValue) \| filter(ParameterValue = -1) \| sort(@Host ASC)

**Срок действия пароля не ограничен:**

filter(Host.Softs\<OracleDBSoft\>) \| select(@Host,
Host.Softs\<OracleDBSoft\>.Databases.DBName,
Host.Softs\<OracleDBSoft\>.Databases.Profiles.Name,
Host.Softs\<OracleDBSoft\>.Databases.Profiles.Parameters.PasswordLifeTime
as ParameterValue) \| filter(ParameterValue = -1) \| sort(@Host ASC)

**Разрешена автоматическая разблокировка учетной записи после
блокировки:**

filter(Host.Softs\<OracleDBSoft\>) \| select(@Host,
Host.Softs\<OracleDBSoft\>.Databases.DBName,
Host.Softs\<OracleDBSoft\>.Databases.Profiles.Name,
Host.Softs\<OracleDBSoft\>.Databases.Profiles.Parameters.PasswordLockTime
as ParameterValue) \| filter(ParameterValue != -1) \| sort(@Host ASC)

**Глубина парольной истории не соответствует требованиям:**

filter(Host.Softs\<OracleDBSoft\>) \| select(@Host,
Host.Softs\<OracleDBSoft\>.Databases.DBName,
Host.Softs\<OracleDBSoft\>.Databases.Profiles.Name,
Host.Softs\<OracleDBSoft\>.Databases.Profiles.Parameters.PasswordReuseMax
as PasswordReuseMaxValue,
Host.Softs\<OracleDBSoft\>.Databases.Profiles.Parameters.PasswordReuseTime
as PasswordReuseTimeValue) \| filter((PasswordReuseMaxValue \< 10 and
PasswordReuseMaxValue != -1 and PasswordReuseTimeValue != -1) or
(PasswordReuseMaxValue = -1 and PasswordReuseTimeValue = -1)) \|
sort(@Host ASC)

**Количество дней, по истечении которых возможно повторное использование
пароля, не соответствует требованиям:**

filter(Host.Softs\<OracleDBSoft\>) \| select(@Host,
Host.Softs\<OracleDBSoft\>.Databases.DBName,
Host.Softs\<OracleDBSoft\>.Databases.Profiles.Name,
Host.Softs\<OracleDBSoft\>.Databases.Profiles.Parameters.PasswordReuseTime
as PasswordReuseTimeValue,
Host.Softs\<OracleDBSoft\>.Databases.Profiles.Parameters.PasswordReuseMax
as PasswordReuseMaxValue) \| filter((PasswordReuseTimeValue \< 180 and
PasswordReuseTimeValue != -1 and PasswordReuseMaxValue != -1) or
(PasswordReuseTimeValue = -1 and PasswordReuseMaxValue = -1)) \|
sort(@Host ASC)

**Системные привилегии роли PUBLIC:**

filter(Host.Softs\<OracleDBSoft\>) \| select(@Host,
Host.Softs\<OracleDBSoft\>.Databases.DBName,
Host.Softs\<OracleDBSoft\>.Databases.SysPrivilegesV2.Grantee as
SysPrivilegesGrantee,
Host.Softs\<OracleDBSoft\>.Databases.SysPrivilegesV2.Name) \|
filter(SysPrivilegesGrantee = \'PUBLIC\') \| sort(@Host ASC)

**Объектные привилегии роли PUBLIC:**

filter(Host.Softs\<OracleDBSoft\>) \| select(@Host,
Host.Softs\<OracleDBSoft\>.Databases.DBName,
Host.Softs\<OracleDBSoft\>.Databases.ObjPrivilegesV2.Grantee as
ObjPrivilegesGrantee,
Host.Softs\<OracleDBSoft\>.Databases.ObjPrivilegesV2.Name,
Host.Softs\<OracleDBSoft\>.Databases.ObjPrivilegesV2.Owner,
Host.Softs\<OracleDBSoft\>.Databases.ObjPrivilegesV2.Object) \|
filter(ObjPrivilegesGrantee = \'PUBLIC\') \| sort(@Host ASC)

**Предоставлен доступ к таблице SYS.AUD\$:**

filter(Host.Softs\<OracleDBSoft\>) \| select(@Host,
Host.Softs\<OracleDBSoft\>.Databases.DBName,
Host.Softs\<OracleDBSoft\>.Databases.ObjPrivilegesV2.Name,
Host.Softs\<OracleDBSoft\>.Databases.ObjPrivilegesV2.Grantee as
ObjPrivilegesGrantee,
Host.Softs\<OracleDBSoft\>.Databases.ObjPrivilegesV2.Grantor,
Host.Softs\<OracleDBSoft\>.Databases.ObjPrivilegesV2.Object as
ObjPrivilegesObject) \| filter(ObjPrivilegesObject = \'AUD\$\' and
ObjPrivilegesGrantee not in \[\'SYS\', \'SYSTEM\', \'DBA\'\]) \|
sort(@Host ASC)

**Предоставлен доступ к таблице SYS.LINK\$:**

filter(Host.Softs\<OracleDBSoft\>) \| select(@Host,
Host.Softs\<OracleDBSoft\>.Databases.DBName,
Host.Softs\<OracleDBSoft\>.Databases.ObjPrivilegesV2.Name,
Host.Softs\<OracleDBSoft\>.Databases.ObjPrivilegesV2.Grantee as
ObjPrivilegesGrantee,
Host.Softs\<OracleDBSoft\>.Databases.ObjPrivilegesV2.Grantor,
Host.Softs\<OracleDBSoft\>.Databases.ObjPrivilegesV2.Object as
ObjPrivilegesObject) \| filter(ObjPrivilegesObject = \'LINK\$\' and
ObjPrivilegesGrantee not in \[\'SYS\', \'SYSTEM\', \'DBA\'\]) \|
sort(@Host ASC)

**Предоставлен доступ к таблице SYS.SOURCE\$:**

filter(Host.Softs\<OracleDBSoft\>) \| select(@Host,
Host.Softs\<OracleDBSoft\>.Databases.DBName,
Host.Softs\<OracleDBSoft\>.Databases.ObjPrivilegesV2.Name,
Host.Softs\<OracleDBSoft\>.Databases.ObjPrivilegesV2.Grantee as
ObjPrivilegesGrantee,
Host.Softs\<OracleDBSoft\>.Databases.ObjPrivilegesV2.Grantor,
Host.Softs\<OracleDBSoft\>.Databases.ObjPrivilegesV2.Object as
ObjPrivilegesObject) \| filter(ObjPrivilegesObject = \'SOURCE\$\' and
ObjPrivilegesGrantee not in \[\'SYS\', \'SYSTEM\', \'DBA\'\]) \|
sort(@Host ASC)

**Предоставлен доступ к таблице SYS.USER_HISTORY\$:**

filter(Host.Softs\<OracleDBSoft\>) \| select(@Host,
Host.Softs\<OracleDBSoft\>.Databases.DBName,
Host.Softs\<OracleDBSoft\>.Databases.ObjPrivilegesV2.Name,
Host.Softs\<OracleDBSoft\>.Databases.ObjPrivilegesV2.Grantee as
ObjPrivilegesGrantee,
Host.Softs\<OracleDBSoft\>.Databases.ObjPrivilegesV2.Grantor,
Host.Softs\<OracleDBSoft\>.Databases.ObjPrivilegesV2.Object as
ObjPrivilegesObject) \| filter(ObjPrivilegesObject = \'USER_HISTORY\$\'
and ObjPrivilegesGrantee not in \[\'SYS\', \'SYSTEM\', \'DBA\'\]) \|
sort(@Host ASC)

**Предоставлен доступ к таблице SYS.USER\$:**

filter(Host.Softs\<OracleDBSoft\>) \| select(@Host,
Host.Softs\<OracleDBSoft\>.Databases.DBName,
Host.Softs\<OracleDBSoft\>.Databases.ObjPrivilegesV2.Name,
Host.Softs\<OracleDBSoft\>.Databases.ObjPrivilegesV2.Grantee as
ObjPrivilegesGrantee,
Host.Softs\<OracleDBSoft\>.Databases.ObjPrivilegesV2.Grantor,
Host.Softs\<OracleDBSoft\>.Databases.ObjPrivilegesV2.Object as
ObjPrivilegesObject) \| filter(ObjPrivilegesObject = \'USER\$\' and
ObjPrivilegesGrantee not in \[\'SYS\', \'SYSTEM\', \'DBA\'\]) \|
sort(@Host ASC)

**МАРШРУТИЗАТОРЫ.**

**Направленная широковещательная передача:**

**(Поддерживаемые системы: Cisco IOS, Cisco IOS XR, Cisco NX-OS, Eltex
MES (ROS), Juniper**

**Junos OS)**

filter(NetworkDeviceHost.HostRoles.Role = \'Router\') \|
select(@NetworkDeviceHost, NetworkDeviceHost.OsName,
NetworkDeviceHost.Interfaces.Id,
NetworkDeviceHost.Interfaces.L3Settings\<NetL3Settings\>.DirectedBroadcast)
\|
filter(NetworkDeviceHost.Interfaces.L3Settings\<NetL3Settings\>.DirectedBroadcast
= True) \| sort(@NetworkDeviceHost ASC, NetworkDeviceHost.Interfaces.Id
ASC)

**Proxy ARP:**

filter(NetworkDeviceHost.HostRoles.Role = \'Router\') \|
select(@NetworkDeviceHost, NetworkDeviceHost.OsName,
NetworkDeviceHost.Interfaces.Id,
NetworkDeviceHost.Interfaces.L3Settings\<NetL3Settings\>.ProxyARP as
ProxyARP) \| filter(ProxyARP = True) \| sort(@NetworkDeviceHost ASC,
NetworkDeviceHost.Interfaces.Id ASC)

**ICMP redirect:**

filter(NetworkDeviceHost.HostRoles.Role = \'Router\') \|
select(@NetworkDeviceHost, NetworkDeviceHost.OsName,
NetworkDeviceHost.Interfaces.Id,
NetworkDeviceHost.Interfaces.L3Settings\<NetL3Settings\>.AddressFamily
as AddressFamily,
NetworkDeviceHost.Interfaces.L3Settings\<NetL3Settings\>.Redirects as
Redirects) \| filter(Redirects = True) \| sort(@NetworkDeviceHost ASC,
NetworkDeviceHost.Interfaces.Id ASC, AddressFamily ASC)

**ICMP unreachable:**

filter(NetworkDeviceHost.HostRoles.Role = \'Router\') \|
select(@NetworkDeviceHost, NetworkDeviceHost.OsName,
NetworkDeviceHost.Interfaces.Id,
NetworkDeviceHost.Interfaces.L3Settings\<NetL3Settings\>.AddressFamily
as AddressFamily,
NetworkDeviceHost.Interfaces.L3Settings\<NetL3Settings\>.Unreachables as
Unreachables) \| filter(Unreachables = True) \| sort(@NetworkDeviceHost
ASC, NetworkDeviceHost.Interfaces.Id ASC, AddressFamily ASC)

**Маршрутизация от исходного адреса:**

filter(NetworkDeviceHost.HostRoles.Role = \'Router\') \|
select(@NetworkDeviceHost, NetworkDeviceHost.OsName,
NetworkDeviceHost.Services.Name as ServiceName,
NetworkDeviceHost.Services.Status as Status) \| filter(ServiceName =
\'source-route\' and Status = True) \| sort(@NetworkDeviceHost ASC)

**Отключена одноадресная пересылка по обратному пути (uRPF):**

filter(NetworkDeviceHost.HostRoles.Role = \'Router\') \|
select(@NetworkDeviceHost, NetworkDeviceHost.OsName,
NetworkDeviceHost.Interfaces.Id,
NetworkDeviceHost.Interfaces.L3Settings\<NetL3Settings\>.AddressFamily
as AddressFamily,
NetworkDeviceHost.Interfaces.L3Settings\<NetL3Settings\>.UrpfMode as
uRPF) \| filter(uRPF = \'none\') \| sort(@NetworkDeviceHost ASC,
NetworkDeviceHost.Interfaces.Id ASC, AddressFamily ASC)

**Аутентификация FHRP не соответствует требованиям:**

filter(NetworkDeviceHost.HostRoles.Role = \'Router\') \|
select(@NetworkDeviceHost, NetworkDeviceHost.@Type as Type,
NetworkDeviceHost.OsName as OsName,
NetworkDeviceHost.Interfaces\<NetInterface\>.Id as Interface,
NetworkDeviceHost.Interfaces\<NetInterface\>.FHRP.Protocol as Protocol,
NetworkDeviceHost.Interfaces\<NetInterface\>.FHRP.Version as Version,
NetworkDeviceHost.Interfaces\<NetInterface\>.FHRP.Group as GroupNumber,
NetworkDeviceHost.Interfaces\<NetInterface\>.FHRP.Authentication as
Authentication) \| filter(Protocol = \'vrrp\' and ((Type = \'IOSHost\'
and Version = 2 or Type in \[\'ComwareHost\', \'VRPHost\',
\'JunosHost\'\]) and Authentication in \[\'simple\', \'none\'\] or Type
in \[\'GAIA\', \'IOSXRHost\', \'NXOSHost\'\] and Authentication =
\'none\') or Protocol = \'hsrp\' and (Authentication = \'none\' or (Type
= \'IOSHost\' or Type = \'NXOSHost\' and Version = 2) and Authentication
= \'simple\')) \| select(@NetworkDeviceHost, OsName, Interface,
Protocol, Version, GroupNumber, Authentication) \|
sort(@NetworkDeviceHost ASC, Interface ASC, Protocol ASC, GroupNumber
ASC)

**BGP: соседи без аутентификации:**

filter((AOSHost or GAIA or IOSHost or VRPHost or JunosHost) and
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:BGP\>)
\| select(@NetworkDeviceHost, NetworkDeviceHost.OsName,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:BGP\>.Protocol,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:BGP\>.InstanceId
as InstanceId,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:BGP\>.AddressFamily
as AddressFamily,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:BGP\>.Type
as Type,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:BGP\>.Neighbors.Address
as Neighbor,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:BGP\>.Neighbors.Password.Value
as Password,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:BGP\>.Neighbors.AuthenticationKeyChain
as KeyChain) \| filter(not Password and (not KeyChain or KeyChain =
\'\')) \| sort(@NetworkDeviceHost ASC, InstanceId ASC, AddressFamily
ASC, Type ASC, Neighbor ASC)

**OSPF: аутентификация областей не соответствует требованиям:**

filter((ASAHost or IOSHost or NXOSHost or VRPHost) and
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:OSPF\>)
\| select(@NetworkDeviceHost, NetworkDeviceHost.OsName,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:OSPF\>.Protocol,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:OSPF\>.InstanceId
as InstanceId,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:OSPF\>.AddressFamily
as AddressFamily,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:OSPF\>.Areas.AreaID
as Area,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:OSPF\>.Areas.AuthenticationType
as AuthType) \| filter(AuthType in \[\'none\', \'simple\'\]) \|
sort(@NetworkDeviceHost ASC, InstanceId ASC, AddressFamily ASC, Area
ASC)

**OSPF: аутентификация интерфейсов не соответствует требованиям:**

filter(NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:OSPF\>)
\| select(@NetworkDeviceHost, NetworkDeviceHost.OsName,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:OSPF\>.Protocol,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:OSPF\>.InstanceId
as InstanceId,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:OSPF\>.AddressFamily
as AddressFamily,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:OSPF\>.Areas.AreaID
as Area,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:OSPF\>.Areas.Interfaces.InterfaceId
as Interface,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:OSPF\>.Areas.Interfaces.AuthenticationType
as AuthType) \| filter(AuthType in \[\'none\', \'simple\'\]) \|
sort(@NetworkDeviceHost ASC, InstanceId ASC, AddressFamily ASC, Area
ASC, Interface ASC)

**OSPF: аутентификация виртуальных каналов не соответствует
требованиям:**

filter((AOSHost or GAIA or IOSHost or NXOSHost or VRPHost or JunosHost)
and
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:OSPF\>)
\| select(@NetworkDeviceHost, NetworkDeviceHost.OsName,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:OSPF\>.Protocol,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:OSPF\>.InstanceId
as InstanceId,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:OSPF\>.AddressFamily
as AddressFamily,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:OSPF\>.Areas.AreaID
as Area,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:OSPF\>.Areas.VirtualLinks.RouterID
as RouterID,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:OSPF\>.Areas.VirtualLinks.AuthenticationType
as AuthType) \| filter(AuthType in \[\'none\', \'simple\'\]) \|
sort(@NetworkDeviceHost ASC, InstanceId ASC, AddressFamily ASC, Area
ASC, RouterID ASC)

**RIP: аутентификация интерфейсов не соответствует требованиям:**

filter(NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:RIP\>)
\| select(@NetworkDeviceHost, NetworkDeviceHost.OsName,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:RIP\>.Protocol,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:RIP\>.InstanceId
as InstanceId,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:RIP\>.AddressFamily
as AddressFamily,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:RIP\>.Interfaces.InterfaceId
as Interface,
NetworkDeviceHost.DynamicRouting\<OperatingSystem:DynamicRouting:RIP\>.Interfaces.AuthenticationType
as AuthType) \| filter(AuthType in \[\'none\', \'simple\'\]) \|
sort(@NetworkDeviceHost ASC, InstanceId ASC, AddressFamily ASC,
Interface ASC)

**EIGRP: интерфейсы без аутентификации:**

filter(NetworkDeviceHost.DynamicRouting\<EIGRP\>) \|
select(@NetworkDeviceHost, NetworkDeviceHost.OsName,
NetworkDeviceHost.DynamicRouting\<EIGRP\>.Protocol,
NetworkDeviceHost.DynamicRouting\<EIGRP\>.InstanceId as InstanceId,
NetworkDeviceHost.DynamicRouting\<EIGRP\>.AddressFamily as
AddressFamily,
NetworkDeviceHost.DynamicRouting\<EIGRP\>.Interfaces.InterfaceId as
Interface,
NetworkDeviceHost.DynamicRouting\<EIGRP\>.Interfaces.AuthenticationType
as AuthType) \| filter(AuthType = \'none\') \| sort(@NetworkDeviceHost
ASC, InstanceId ASC, AddressFamily ASC, Interface ASC)

**КОММУТАТОРЫ.**

**Защита портов не включена (проверка по умолчанию):**

filter(not IOSHost and NetworkDeviceHost.HostRoles.Role = \'Switch\') \|
select(@NetworkDeviceHost, NetworkDeviceHost.OsName,
NetworkDeviceHost.Interfaces.Id,
NetworkDeviceHost.Interfaces.L2Settings\<NetL2Settings\>.Mode as Mode,
NetworkDeviceHost.Interfaces.L2Settings\<NetL2Settings\>.PortSecurity.Status
as PortSecurityEnabled) \| filter(Mode = \'access\' and
PortSecurityEnabled = False) \| sort(@NetworkDeviceHost ASC,
NetworkDeviceHost.Interfaces.Id ASC)

**Защита портов не включена (Cisco IOS):**

filter(IOSHost.HostRoles.Role = \'Switch\') \|
select(@NetworkDeviceHost, NetworkDeviceHost.OsName,
NetworkDeviceHost.Interfaces.Id,
NetworkDeviceHost.Interfaces.L2Settings\<NetL2Settings\>.ConfiguredMode
as ConfiguredMode,
NetworkDeviceHost.Interfaces.L2Settings\<NetL2Settings\>.PortSecurity.Status
as PortSecurityEnabled) \| filter(ConfiguredMode = \'access\' and
PortSecurityEnabled = False) \| sort(@NetworkDeviceHost ASC,
NetworkDeviceHost.Interfaces.Id ASC)

**Отключен DHCP snooping:**

filter(NetworkDeviceHost.HostRoles.Role = \'Switch\') \|
select(@NetworkDeviceHost, NetworkDeviceHost.OsName,
NetworkDeviceHost.Services\<DHCPSnooping\>.Name,
NetworkDeviceHost.Services\<DHCPSnooping\>.Status) \|
filter(NetworkDeviceHost.Services\<DHCPSnooping\>.Status = False) \|
sort(@NetworkDeviceHost ASC)

**Небезопасные протоколы управления.**

**Доступ по протоколу Telnet (проверка по умолчанию):**

filter(GAIA or NXOSHost or WLCHost or EltexHost or JunosHost or
NortelHost) \| select(@NetworkDeviceHost, NetworkDeviceHost.OsName,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:Telnet\>.Name,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:Telnet\>.Status
as Status) \| filter(Status = True) \| sort(@NetworkDeviceHost ASC)

**Доступ по протоколу Telnet (Cisco IOS):**

filter(IOSHost) \| select(@IOSHost, IOSHost.OsName,
IOSHost.TerminalLines.Type as LineType, IOSHost.TerminalLines.Number as
LineNumber, IOSHost.TerminalLines.TransportInput as TransportInput) \|
filter(LineType = \'vty\' and TransportInput in \[\'telnet\', \'all\'\])
\| sort(@IOSHost ASC, LineType ASC, LineNumber ASC)

**Доступ по протоколу Telnet (Cisco ASA):**

filter(ASAHost) \| select(@ASAHost, ASAHost.Services\<ASATelnet\>.Name,
ASAHost.Services\<ASATelnet\>.AllowedAddresses as AllowedAddresses) \|
filter(AllowedAddresses) \| sort(@ASAHost ASC, AllowedAddresses ASC)

**Доступ по протоколу HTTP:**

filter(NetworkDeviceHost) \| select(@NetworkDeviceHost,
NetworkDeviceHost.OsName,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:WebManagement\>.Name
as ServiceName,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:WebManagement\>.Status
as Status) \| filter(ServiceName = \'http\' and Status = True) \|
sort(@NetworkDeviceHost ASC)

**Доступ по протоколу TFTP (Cisco IOS):**

filter(IOSHost) \| select(@IOSHost, IOSHost.OsName,
IOSHost.Services\<TFTP\>.Name, IOSHost.Services\<TFTP\>.Status) \|
filter(IOSHost.Services\<TFTP\>.Status = True) \| sort(@IOSHost ASC)

**Доступ по протоколу SSH версии 1:**

filter(NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:SSH\>.Versions
contains 1) \| select(@NetworkDeviceHost, NetworkDeviceHost.OsName,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:SSH\>.Name,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:SSH\>.Status,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:SSH\>.Versions
as Versions) \|
filter(NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:SSH\>.Status
= True) \| sort(@NetworkDeviceHost ASC, Versions ASC)

**Не заданы списки доступа для IOS и VRP (IPv4):**

filter((IOSHost or VRPHost) and NetworkDeviceHost.TerminalLines\[Type =
\'vty\' and not AccessClasses\[AddressFamily = \'Ipv4\' and Direction =
\'In\'\]\]) \| select(@NetworkDeviceHost, NetworkDeviceHost.OsName,
NetworkDeviceHost.TerminalLines.Type as LineType,
NetworkDeviceHost.TerminalLines.Number as LineNumber,
NetworkDeviceHost.TerminalLines.AccessClasses.Name,
NetworkDeviceHost.TerminalLines.AccessClasses.AddressFamily as
AddressFamily, NetworkDeviceHost.TerminalLines.AccessClasses.Direction
as Direction) \| filter(LineType = \'vty\') \| sort(@NetworkDeviceHost
ASC, LineNumber ASC, AddressFamily ASC, Direction ASC)

**Не заданы списки доступа для IOS и VRP (IPv4 и IPv6):**

filter((IOSHost or VRPHost) and NetworkDeviceHost.TerminalLines\[Type =
\'vty\' and (not AccessClasses\[AddressFamily = \'Ipv4\' and Direction =
\'In\'\] or not AccessClasses\[AddressFamily = \'Ipv6\' and Direction =
\'In\'\])\]) \| select(@NetworkDeviceHost, NetworkDeviceHost.OsName,
NetworkDeviceHost.TerminalLines.Type as LineType,
NetworkDeviceHost.TerminalLines.Number as LineNumber,
NetworkDeviceHost.TerminalLines.AccessClasses.Name,
NetworkDeviceHost.TerminalLines.AccessClasses.AddressFamily as
AddressFamily, NetworkDeviceHost.TerminalLines.AccessClasses.Direction
as Direction) \| filter(LineType = \'vty\') \| sort(@NetworkDeviceHost
ASC, LineNumber ASC, AddressFamily ASC, Direction ASC)

**Не заданы списки доступа для NX-OS (IPv4):**

filter(NXOSHost.TerminalLines\[Type = \'vty\' and not
AccessClasses\[AddressFamily = \'Ipv4\' and Direction = \'In\'\]\] and
NXOSHost.Interfaces\[Id = \'mgmt0\' and not AccessLists\[AddressFamily =
\'Ipv4\' and Direction = \'In\'\]\]) \| select(@NXOSHost,
NXOSHost.TerminalLines.Type as LineType,
NXOSHost.TerminalLines.AccessClasses.Name,
NXOSHost.TerminalLines.AccessClasses.AddressFamily as LineAclAF,
NXOSHost.TerminalLines.AccessClasses.Direction as LineAclDirection,
NXOSHost.Interfaces.Id, NXOSHost.Interfaces.AccessLists.Name,
NXOSHost.Interfaces.AccessLists.AddressFamily as InterfaceAclAF,
NXOSHost.Interfaces.AccessLists.Direction as InterfaceAclDirection) \|
filter((LineType = \'vty\' and (not LineAclDirection or LineAclDirection
= \'In\')) or (NXOSHost.Interfaces.Id = \'mgmt0\' and (not
InterfaceAclDirection or InterfaceAclDirection = \'In\'))) \|
sort(@NXOSHost ASC, LineAclAF ASC, InterfaceAclAF ASC)

**Не заданы списки доступа для NX-OS (IPv4 и IPv6):**

filter(NXOSHost.TerminalLines\[Type = \'vty\' and (not
AccessClasses\[AddressFamily = \'Ipv4\' and Direction = \'In\'\] or not
AccessClasses\[AddressFamily = \'Ipv6\' and Direction = \'In\'\])\] and
NXOSHost.Interfaces\[Id = \'mgmt0\' and (not AccessLists\[AddressFamily
= \'Ipv4\' and Direction = \'In\'\] or not AccessLists\[AddressFamily =
\'Ipv6\' and Direction = \'In\'\])\]) \| select(@NXOSHost,
NXOSHost.TerminalLines.Type as LineType,
NXOSHost.TerminalLines.AccessClasses.Name,
NXOSHost.TerminalLines.AccessClasses.AddressFamily as LineAclAF,
NXOSHost.TerminalLines.AccessClasses.Direction as LineAclDirection,
NXOSHost.Interfaces.Id, NXOSHost.Interfaces.AccessLists.Name,
NXOSHost.Interfaces.AccessLists.AddressFamily as InterfaceAclAF,
NXOSHost.Interfaces.AccessLists.Direction as InterfaceAclDirection) \|
filter((LineType = \'vty\' and (not LineAclDirection or LineAclDirection
= \'In\'))

or (NXOSHost.Interfaces.Id = \'mgmt0\' and (not InterfaceAclDirection or
InterfaceAclDirection = \'In\'))) \| sort(@NXOSHost ASC, LineAclAF ASC,
InterfaceAclAF ASC)

**Управление с любых адресов для GAiA:**

filter(GAIA.AllowedHosts.Prefix = 0) \| select(@GAIA, GAIA.AllowedHosts,
GAIA.AllowedHosts.Prefix) \| sort(@GAIA ASC, GAIA.AllowedHosts.Prefix
DESC, GAIA.AllowedHosts ASC)

**Тайм-аут простоя SSH не соответствует требованиям:**

filter(CheckPointHost or ASAHost) \| select(@NetworkDeviceHost,
NetworkDeviceHost.OsName,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:SSH\>.Name,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:SSH\>.Status
as Status,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:SSH\>.IdleTimeout
as IdleTimeout) \| filter(Status and IdleTimeout \> 600) \|
sort(@NetworkDeviceHost ASC)

**Тайм-аут простоя HTTPS не соответствует требованиям:**

filter(GAIA or ASAHost or JunosHost) \| select(@NetworkDeviceHost,
NetworkDeviceHost.OsName,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:WebManagement\>.Name
as ServiceName,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:WebManagement\>.Status
as Status,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:WebManagement\>.IdleTimeout
as IdleTimeout) \| filter(ServiceName = \'https\' and Status = True and
IdleTimeout \> 600) \| sort(@NetworkDeviceHost ASC)

**Тайм-аут простоя на линиях не соответствует требованиям:**

filter(IOSHost or IOSXRHost or NXOSHost or VRPHost) \|
select(@NetworkDeviceHost, NetworkDeviceHost.OsName,
NetworkDeviceHost.TerminalLines.Type as LineType,
NetworkDeviceHost.TerminalLines.Number as LineNumber,
NetworkDeviceHost.TerminalLines.IdleTimeout.Minutes as Minutes,
NetworkDeviceHost.TerminalLines.IdleTimeout.Seconds as Seconds) \|
filter(LineType and (Minutes \> 10 or (not Minutes or Minutes = 0) and
(not Seconds or Seconds = 0))) \| sort(@NetworkDeviceHost ASC, LineType
ASC, LineNumber ASC)

**Тайм-аут простоя Telnet и SSH не соответствует требованиям (Cisco
WLC):**

filter(WLCHost\[SessionTimeout = 0 or SessionTimeout \> 10\]) \|
select(@WLCHost, WLCHost.OsName, WLCHost.SessionTimeout) \|
sort(@WLCHost ASC)

**SNMP.**

**Устаревшие версии SNMP:**

filter(NetworkDeviceHost) \| select(@NetworkDeviceHost,
NetworkDeviceHost.OsName, NetworkDeviceHost.Services\<SNMP\>.Name,
NetworkDeviceHost.Services\<SNMP\>.Status as Status,
NetworkDeviceHost.Services\<SNMP\>.EnabledVersions as Versions) \|
filter(Status = True and Versions in \[\'v1\', \'v2c\'\]) \|
sort(@NetworkDeviceHost ASC, Versions ASC)

**Недостаточный уровень безопасности для групп:**

filter(ASAHost or IOSHost or IOSXRHost or VRPHost or JunosHost) \|
select(@NetworkDeviceHost, NetworkDeviceHost.OsName,
NetworkDeviceHost.Services\<SNMP\>.Name,
NetworkDeviceHost.Services\<SNMP\>.Status as Status,
NetworkDeviceHost.Services\<SNMP\>.Groups.Name as SNMPGroup,
NetworkDeviceHost.Services\<SNMP\>.Groups.Contexts.ContextName as
Context,
NetworkDeviceHost.Services\<SNMP\>.Groups.Contexts.VacmAccess.SecurityModel
as SecurityModel,
NetworkDeviceHost.Services\<SNMP\>.Groups.Contexts.VacmAccess.SecurityLevel
as SecurityLevel) \| filter(Status = True and (not SNMPGroup or
SecurityModel != \'v3\' or SecurityLevel != \'AuthPriv\')) \|
sort(@NetworkDeviceHost ASC, SNMPGroup ASC, Context ASC, SecurityModel
ASC, SecurityLevel ASC)

**Протокол шифрования не соответствует требованиям:**

filter(AOSHost or ASAHost or IOSHost or IOSXRHost or NXOSHost or WLCHost
or VRPHost or JunosHost or NortelHost) \| select(@NetworkDeviceHost,
NetworkDeviceHost.OsName, NetworkDeviceHost.Services\<SNMP\>.Name,
NetworkDeviceHost.Services\<SNMP\>.Status as Status,
NetworkDeviceHost.Services\<SNMP\>.Users.Name as User,
NetworkDeviceHost.Services\<SNMP\>.Users.Privacy as Privacy) \|
filter(Status = True and not Privacy like \'aes%\' and not Privacy =
\'3des\') \| sort(@NetworkDeviceHost ASC, User ASC)

**Не заданы списки доступа для пользователей (IPv4):**

filter(IOSHost or IOSXRHost or VRPHost) \| select(@NetworkDeviceHost,
NetworkDeviceHost.OsName, NetworkDeviceHost.Services\<SNMP\>.Name,
NetworkDeviceHost.Services\<SNMP\>.Status as Status,
NetworkDeviceHost.Services\<SNMP\>.Users.Name as User,
NetworkDeviceHost.Services\<SNMP\>.Users.IPv4AccessList as IPv4ACL,
NetworkDeviceHost.Services\<SNMP\>.Users.IPv6AccessList as IPv6ACL) \|
filter(Status = True and User and (not IPv4ACL or IPv4ACL = \'\')) \|
sort(@NetworkDeviceHost ASC, User ASC)

**Не заданы списки доступа для пользователей (IPv4 и IPv6):**

filter(IOSHost or IOSXRHost or VRPHost) \| select(@NetworkDeviceHost,
NetworkDeviceHost.OsName, NetworkDeviceHost.Services\<SNMP\>.Name,
NetworkDeviceHost.Services\<SNMP\>.Status as Status,
NetworkDeviceHost.Services\<SNMP\>.Users.Name as User,
NetworkDeviceHost.Services\<SNMP\>.Users.IPv4AccessList as IPv4ACL,
NetworkDeviceHost.Services\<SNMP\>.Users.IPv6AccessList as IPv6ACL) \|
filter(Status = True and User and (not IPv4ACL or IPv4ACL = \'\' or not
IPv6ACL or IPv6ACL = \'\')) \| sort(@NetworkDeviceHost ASC, User ASC)

**Не заданы списки доступа для групп (IPv4):**

filter(IOSHost or IOSXRHost or VRPHost) \| select(@NetworkDeviceHost,
NetworkDeviceHost.OsName, NetworkDeviceHost.Services\<SNMP\>.Name,
NetworkDeviceHost.Services\<SNMP\>.Status as Status,
NetworkDeviceHost.Services\<SNMP\>.Groups.Name as SNMPGroup,
NetworkDeviceHost.Services\<SNMP\>.Groups.Contexts.ContextName as
Context,
NetworkDeviceHost.Services\<SNMP\>.Groups.Contexts.VacmAccess.SecurityModel
as SecurityModel,
NetworkDeviceHost.Services\<SNMP\>.Groups.Contexts.VacmAccess.SecurityLevel
as SecurityLevel,
NetworkDeviceHost.Services\<SNMP\>.Groups.Contexts.VacmAccess.IPv4AccessList
as IPv4ACL,
NetworkDeviceHost.Services\<SNMP\>.Groups.Contexts.VacmAccess.IPv6AccessList
as IPv6ACL) \| filter(Status = True and SNMPGroup and (not IPv4ACL or
IPv4ACL = \'\')) \| sort(@NetworkDeviceHost ASC, SNMPGroup ASC, Context
ASC, SecurityModel ASC, SecurityLevel ASC)

**Не заданы списки доступа для групп (IPv4 и IPv6):**

filter(IOSHost or IOSXRHost or VRPHost) \| select(@NetworkDeviceHost,
NetworkDeviceHost.OsName, NetworkDeviceHost.Services\<SNMP\>.Name,
NetworkDeviceHost.Services\<SNMP\>.Status as Status,
NetworkDeviceHost.Services\<SNMP\>.Groups.Name as SNMPGroup,
NetworkDeviceHost.Services\<SNMP\>.Groups.Contexts.ContextName as
Context,
NetworkDeviceHost.Services\<SNMP\>.Groups.Contexts.VacmAccess.SecurityModel
as SecurityModel,
NetworkDeviceHost.Services\<SNMP\>.Groups.Contexts.VacmAccess.SecurityLevel
as SecurityLevel,
NetworkDeviceHost.Services\<SNMP\>.Groups.Contexts.VacmAccess.IPv4AccessList
as IPv4ACL,
NetworkDeviceHost.Services\<SNMP\>.Groups.Contexts.VacmAccess.IPv6AccessList
as IPv6ACL) \| filter(Status = True and SNMPGroup and (not IPv4ACL or
IPv4ACL = \'\' or not IPv6ACL or IPv6ACL = \'\')) \|
sort(@NetworkDeviceHost ASC, SNMPGroup ASC, Context ASC, SecurityModel
ASC, SecurityLevel ASC)

**Стандартные строки сообщества:**

filter(NetworkDeviceHost) \| select(@NetworkDeviceHost,
NetworkDeviceHost.OsName, NetworkDeviceHost.Services\<SNMP\>.Name,
NetworkDeviceHost.Services\<SNMP\>.Status as Status,
NetworkDeviceHost.Services\<SNMP\>.Communities.Name as Community,
NetworkDeviceHost.Services\<SNMP\>.Communities.AccessPermissions) \|
filter(Status = True and Community in
\[\'private\',\'public\',\'cisco\',\'manage\',\'ILMI\',\'cable-docsis\',\'userpasswd\',\'securepasswd\',\'secure\',\'user\'\])
\| sort(@NetworkDeviceHost ASC, Community ASC)

**Доступ на запись по SNMP:**

filter(NetworkDeviceHost) \| select(@NetworkDeviceHost,
NetworkDeviceHost.OsName, NetworkDeviceHost.Services\<SNMP\>.Name,
NetworkDeviceHost.Services\<SNMP\>.Status as Status,
NetworkDeviceHost.Services\<SNMP\>.Communities.Name as Community,
NetworkDeviceHost.Services\<SNMP\>.Communities.AccessPermissions as
Access) \| filter(Status = True and Access = \'RW\') \|
sort(@NetworkDeviceHost ASC, Community ASC)

**Не заданы списки доступа для сообществ (IPv4):**

filter(IOSHost or IOSXRHost or NXOSHost or VRPHost) \|
select(@NetworkDeviceHost, NetworkDeviceHost.OsName,
NetworkDeviceHost.Services\<SNMP\>.Name,
NetworkDeviceHost.Services\<SNMP\>.Status as Status,
NetworkDeviceHost.Services\<SNMP\>.Communities.Name as Community,
NetworkDeviceHost.Services\<SNMP\>.Communities.AccessPermissions,
NetworkDeviceHost.Services\<SNMP\>.Communities.IPv4AccessList as
IPv4ACL, NetworkDeviceHost.Services\<SNMP\>.Communities.IPv6AccessList
as IPv6ACL) \| filter(Status = True and Community and (not IPv4ACL or
IPv4ACL = \'\')) \| sort(@NetworkDeviceHost ASC, Community ASC)

**Не заданы списки доступа для сообществ (IPv4 и IPv6):**

filter(IOSHost or IOSXRHost or NXOSHost or VRPHost) \|
select(@NetworkDeviceHost, NetworkDeviceHost.OsName,
NetworkDeviceHost.Services\<SNMP\>.Name,
NetworkDeviceHost.Services\<SNMP\>.Status as Status,
NetworkDeviceHost.Services\<SNMP\>.Communities.Name as Community,
NetworkDeviceHost.Services\<SNMP\>.Communities.AccessPermissions,
NetworkDeviceHost.Services\<SNMP\>.Communities.IPv4AccessList as
IPv4ACL, NetworkDeviceHost.Services\<SNMP\>.Communities.IPv6AccessList
as IPv6ACL) \| filter(Status = True and Community and (not IPv4ACL or
IPv4ACL = \'\' or not IPv6ACL or IPv6ACL = \'\')) \|
sort(@NetworkDeviceHost ASC, Community ASC)

**ПАРАМЕТРЫ ЖУРНАЛИРОВАНИЯ.**

**Служба журналирования отключена:**

filter(NetworkDeviceHost) \| select(@NetworkDeviceHost,
NetworkDeviceHost.OsName,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:Logging\>.Name,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:Logging\>.Status
as Status) \| filter(Status = False) \| sort(@NetworkDeviceHost ASC)

**Не задан сервер syslog (проверка по умолчанию):**

filter(AOSHost or ADEHost or ASAHost or IOSHost or IOSXRHost or NXOSHost
or EltexHost or FortigateHost or ComwareHost or VRPHost or JunosHost) \|
select(@NetworkDeviceHost, NetworkDeviceHost.OsName,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:Logging\>.Name,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:Logging\>.Status
as Status,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:Logging\>.LoggingServers
as LoggingServers) \| filter(Status and not LoggingServers) \|
sort(@NetworkDeviceHost ASC)

**Уровень важности регистрируемых событий не соответствует требованиям
(проверка по умолчанию):**

filter(AOSHost or ADEHost or ASAHost or IOSHost or IOSXRHost) \|
select(@NetworkDeviceHost, NetworkDeviceHost.OsName,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:Logging\>.Name,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:Logging\>.Status
as Status,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:Logging\>.DestinationSettings.Destination
as Destination,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:Logging\>.DestinationSettings.Severity
as Severity) \| filter(Status and (not Destination or Destination =
\'trap\' and not Severity = \'informational\' and not Severity like
\'debug%\')) \| sort(@NetworkDeviceHost ASC)

**Уровень важности регистрируемых событий для сервера не соответствует
требованиям**

**Построить виджет:**

filter(IOSXRHost or NXOSHost or ESRHost or FortigateHost) \|
select(@NetworkDeviceHost, NetworkDeviceHost.OsName,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:Logging\>.Name,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:Logging\>.Status
as Status,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:Logging\>.LoggingServers.Address
as Address,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:Logging\>.LoggingServers.VRF
as Instance,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:Logging\>.LoggingServers.Severity
as Severity) \| filter(not Severity in \[\'informational\',
\'debugging\'\]) \| sort(@NetworkDeviceHost ASC, Address ASC, Instance
ASC)

**Уровень важности регистрируемых событий не соответствует требованиям
(Junos):**

filter(JunosHost) \| select(@JunosHost, JunosHost.OsName,
JunosHost.Services\<OperatingSystem:NetworkDevice:Logging\>.Name,
JunosHost.Services\<OperatingSystem:NetworkDevice:Logging\>.Status as
Status,
JunosHost.Services\<OperatingSystem:NetworkDevice:Logging\>.LoggingServers\<OperatingSystem:Juniper:Junos:LoggingServer\>.Address
as Address,
JunosHost.Services\<OperatingSystem:NetworkDevice:Logging\>.LoggingServers\<OperatingSystem:Juniper:Junos:LoggingServer\>.VRF
as LogicalSystem,
JunosHost.Services\<OperatingSystem:NetworkDevice:Logging\>.LoggingServers\<OperatingSystem:Juniper:Junos:LoggingServer\>.LoggingLevels.Facility
as Facility,
JunosHost.Services\<OperatingSystem:NetworkDevice:Logging\>.LoggingServers\<OperatingSystem:Juniper:Junos:LoggingServer\>.LoggingLevels.Severity
as Severity) \| filter(not Severity in \[\'informational\',
\'debugging\'\]) \| sort(@JunosHost ASC, Address ASC, LogicalSystem ASC,
Facility ASC)

**Уровень важности регистрируемых событий не соответствует требованиям
(VRP):**

filter(VRPHost) \| select(@VRPHost, VRPHost.OsName as OsName,
VRPHost.Services\<OperatingSystem:NetworkDevice:Logging\>.Name as
ServiceName,
VRPHost.Services\<OperatingSystem:NetworkDevice:Logging\>.Status as
Status,
VRPHost.Services\<OperatingSystem:NetworkDevice:Logging\>.LoggingServers\<OperatingSystem:Huawei:VRP:LoggingServer\>.Address
as Address,
VRPHost.Services\<OperatingSystem:NetworkDevice:Logging\>.LoggingServers\<OperatingSystem:Huawei:VRP:LoggingServer\>.VRF
as Instance,
VRPHost.Services\<OperatingSystem:NetworkDevice:Logging\>.LoggingServers\<OperatingSystem:Huawei:VRP:LoggingServer\>.Channel
as Channel) \| join(select(@VRPHost, VRPHost.Channels.Number as Number,
VRPHost.Channels.Name as ChannelName,
VRPHost.Channels.ChannelSources.ModuleName as ModuleName,
VRPHost.Channels.ChannelSources.LoggingState as State,
VRPHost.Channels.ChannelSources.LoggingSeverityLevel as Severity) as
Channels, \@VRPHost = Channels.@VRPHost and Channel = Channels.Number)
\| filter(Channel and (not Channels.State or Channels.State = False or
not Channels.Severity in \[\'informational\', \'debugging\'\])) \|
select(@VRPHost, OsName, ServiceName, Status, Address, Instance,
Channel, Channels.ChannelName, Channels.ModuleName as ModuleName,
Channels.State, Channels.Severity) \| sort(@VRPHost ASC, Address ASC,
Instance ASC, ModuleName ASC)

**Уровень важности регистрируемых событий не соответствует требованиям
(Comware):**

filter(ComwareHost) \| select(@ComwareHost, ComwareHost.OsName as
OsName,
ComwareHost.Services\<OperatingSystem:NetworkDevice:Logging\>.Name as
ServiceName,
ComwareHost.Services\<OperatingSystem:NetworkDevice:Logging\>.Status as
Status,
ComwareHost.Services\<OperatingSystem:NetworkDevice:Logging\>.LoggingServers\<OperatingSystem:HP:Comware:LoggingServer\>.Address
as Address,
ComwareHost.Services\<OperatingSystem:NetworkDevice:Logging\>.LoggingServers\<OperatingSystem:HP:Comware:LoggingServer\>.VRF
as Instance,
ComwareHost.Services\<OperatingSystem:NetworkDevice:Logging\>.LoggingServers\<OperatingSystem:HP:Comware:LoggingServer\>.Channel
as Channel) \| join(select(@ComwareHost, ComwareHost.Channels.Number as
Number, ComwareHost.Channels.Name as ChannelName,
ComwareHost.Channels.ChannelSources.ModuleName as ModuleName,
ComwareHost.Channels.ChannelSources.LoggingState as State,
ComwareHost.Channels.ChannelSources.LoggingSeverityLevel as Severity) as
Channels, \@ComwareHost = Channels.@ComwareHost and Channel =
Channels.Number) \| filter(Channel and (not Channels.State or
Channels.State = False or not Channels.Severity in \[\'informational\',
\'debugging\'\])) \| select(@ComwareHost, OsName, ServiceName, Status,
Address, Instance, Channel, Channels.ChannelName, Channels.ModuleName as
ModuleName, Channels.State, Channels.Severity) \| sort(@ComwareHost ASC,
Address ASC, Instance ASC, ModuleName ASC)

**Параметры меток времени не соответствуют требованиям (проверка по
умолчанию):**

filter(IOSHost or IOSXRHost or WLCHost or ComwareHost or VRPHost) \|
select(@NetworkDeviceHost, NetworkDeviceHost.OsName,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:Logging\>.Name,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:Logging\>.Status
as Status,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:Logging\>.TimestampSettings.LogType
as LogType,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:Logging\>.TimestampSettings.Timestamp
as Timestamp,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:Logging\>.TimestampSettings.DisplayYear
as Year,
NetworkDeviceHost.Services\<OperatingSystem:NetworkDevice:Logging\>.TimestampSettings.Raw)
\| filter(Status and (Timestamp != \'datetime\' or Year = False)) \|
sort(@NetworkDeviceHost ASC, LogType ASC)

**Отключены метки времени (Cisco ASA):**

filter(ASAHost) \| select(@ASAHost, ASAHost.OsName,
ASAHost.Services\<ASALogging\>.Name,
ASAHost.Services\<ASALogging\>.Status as Status,
ASAHost.Services\<ASALogging\>.Timestamps as Timestamps) \|
filter(Timestamps = False) \| sort(@ASAHost ASC)

**ПРОТОКОЛЫ ОБНАРУЖЕНИЯ СОСЕДЕЙ.**

**Включен протокол CDP:**

filter(IOSHost or IOSXRHost or NXOSHost or WLCHost) \|
select(@CiscoHost, CiscoHost.OsName, CiscoHost.Services.Name as
ServiceName, CiscoHost.Services.Status as Status) \| filter(ServiceName
= \'cdp\' and Status = True) \| sort(@CiscoHost ASC)

**Включен протокол LLDP:**

filter(IOSHost or IOSXRHost or NXOSHost or EltexHost or ComwareHost or
VRPHost or JunosHost) \| select(@NetworkDeviceHost,
NetworkDeviceHost.OsName, NetworkDeviceHost.Services.Name as
ServiceName, NetworkDeviceHost.Services.Status as Status) \|
filter(ServiceName = \'lldp\' and Status = True) \|
sort(@NetworkDeviceHost ASC)

**NTP.**

**Задано менее двух серверов NTP:**

filter(AOSHost or GAIA or ADEHost or ASAHost or IOSHost or IOSXRHost or
NXOSHost or EltexHost or ComwareHost or VRPHost or JunosHost) \|
select(@NetworkDeviceHost, NetworkDeviceHost.OsName as OsName,
NetworkDeviceHost.Services\<NTP\>.Name,
NetworkDeviceHost.Services\<NTP\>.Status as Status,
NetworkDeviceHost.Services\<NTP\>.ServerRecords.VRF,
NetworkDeviceHost.Services\<NTP\>.ServerRecords.NTPServers.Address as
Server) \| group(@NetworkDeviceHost, OsName, Status, COUNT(Server) as
NumServers) \| filter(Status = False or (Status and NumServers \< 2)) \|
select(@NetworkDeviceHost, OsName, NumServers) \|
sort(@NetworkDeviceHost ASC)

**Аутентификация NTP не соответствует требованиям (проверка по
умолчанию):**

filter(ADEHost or ASAHost or IOSHost or IOSXRHost or NXOSHost or MESHost
or ComwareHost or VRPHost or JunosHost) \| select(@NetworkDeviceHost,
NetworkDeviceHost.OsName as OsName,
NetworkDeviceHost.Services\<NTP\>.Name as ServiceName,
NetworkDeviceHost.Services\<NTP\>.Status as Status,
NetworkDeviceHost.Services\<NTP\>.Authentication as Authentication,
NetworkDeviceHost.Services\<NTP\>.ServerRecords.VRF as Instance,
NetworkDeviceHost.Services\<NTP\>.ServerRecords.NTPServers.Address as
Server, NetworkDeviceHost.Services\<NTP\>.ServerRecords.NTPServers.Key
as Key) \| join(select(@NetworkDeviceHost,
NetworkDeviceHost.Services\<NTP\>.AuthenticationKeys.Number as Key) as
Defined, \@NetworkDeviceHost = Defined.@NetworkDeviceHost and Key =
Defined.Key) \| join(select(@NetworkDeviceHost,
NetworkDeviceHost.Services\<NTP\>.TrustedKeys.Values as Key) as Trusted,
\@NetworkDeviceHost = Trusted.@NetworkDeviceHost and Key = Trusted.Key)
\| filter(Status and (Authentication = False or not Defined.Key or not
Trusted.Key)) \| select(@NetworkDeviceHost, OsName, ServiceName, Status,
Authentication, Instance, Server, Key, Defined.Key, Trusted.Key) \|
sort(@NetworkDeviceHost ASC, Instance ASC, Server ASC)

**Аутентификация NTP не соответствует требованиям (AOS):**

filter(AOSHost) \| select(@NetworkDeviceHost, NetworkDeviceHost.OsName
as OsName, NetworkDeviceHost.Services\<NTP\>.Name as ServiceName,
NetworkDeviceHost.Services\<NTP\>.Status as Status,
NetworkDeviceHost.Services\<NTP\>.Authentication as Authentication,
NetworkDeviceHost.Services\<NTP\>.ServerRecords.VRF as Instance,
NetworkDeviceHost.Services\<NTP\>.ServerRecords.NTPServers.Address as
Server, NetworkDeviceHost.Services\<NTP\>.ServerRecords.NTPServers.Key
as Key) \| join(select(@NetworkDeviceHost,
NetworkDeviceHost.Services\<NTP\>.TrustedKeys.Values as Key) as Trusted,
\@NetworkDeviceHost = Trusted.@NetworkDeviceHost and Key = Trusted.Key)
\| filter(Status and (Authentication = False or not Trusted.Key)) \|
select(@NetworkDeviceHost, OsName, ServiceName, Status, Authentication,
Instance, Server, Key, Trusted.Key) \| sort(@NetworkDeviceHost ASC,
Instance ASC, Server ASC)

**ПАРОЛЬНЫЕ ПОЛИТИКИ.**

**Не задан пароль для повышения привилегий:**

filter((ASAHost or IOSHost or VRPHost) and not
NetworkDeviceHost.PrivilegedPasswords) \| select(@NetworkDeviceHost,
NetworkDeviceHost.OsName, NetworkDeviceHost.PrivilegedPasswords) \|
sort(@NetworkDeviceHost ASC)

**Отключено шифрование паролей (Cisco IOS):**

filter(IOSHost) \| select(@IOSHost, IOSHost.OsName,
IOSHost.Services.Name as ServiceName, IOSHost.Services.Status as Status)
\| filter(ServiceName = \'password-encryption\' and Status = False) \|
sort(@IOSHost ASC)

**Алгоритм шифрования паролей не соответствует требованиям (JunOS):**

filter(JunosHost) \| select(@JunosHost, JunosHost.OsName,
JunosHost.PasswordPolicy\<OperatingSystem:Juniper:Junos:PasswordPolicy\>.Encryption
as Encryption) \| filter(Encryption in \[\'md5\', \'sha1\'\]) \|
sort(@JunosHost ASC)

**Минимальная длина пароля не соответствует требованиям:**

filter(NetworkDeviceHost) \| select(@NetworkDeviceHost,
NetworkDeviceHost.OsName as OsName,
NetworkDeviceHost.PasswordPolicy.Complexity.MinLength as MinLength) \|
filter(MinLength \< 8) \| sort(@NetworkDeviceHost ASC)

**Минимальное количество символов для каждого символьного класса не
соответствует требованиям:**

filter(NetworkDeviceHost) \| select(@NetworkDeviceHost,
NetworkDeviceHost.OsName as OsName,
NetworkDeviceHost.PasswordPolicy.Complexity.MinUpper as MinUpper,
NetworkDeviceHost.PasswordPolicy.Complexity.MinLower as MinLower,
NetworkDeviceHost.PasswordPolicy.Complexity.MinNumeric as MinNumeric,
NetworkDeviceHost.PasswordPolicy.Complexity.MinSpecial as MinSpecial) \|
filter(MinUpper \< 1 or MinLower \< 1 or MinNumeric \< 1 or MinSpecial
\< 1) \| sort(@NetworkDeviceHost ASC)

**Минимальное количество символьных классов не соответствует
требованиям:**

filter(NetworkDeviceHost) \| select(@NetworkDeviceHost,
NetworkDeviceHost.OsName as OsName,
NetworkDeviceHost.PasswordPolicy.Complexity.MinClasses as MinClasses) \|
filter(MinClasses \< 3) \| sort(@NetworkDeviceHost ASC)

**Не запрещено использование имени пользователя в пароле:**

filter(NetworkDeviceHost) \| select(@NetworkDeviceHost,
NetworkDeviceHost.OsName as OsName,
NetworkDeviceHost.PasswordPolicy.Complexity.NoUsername as NoUsername) \|
filter(NoUsername = False) \| sort(@NetworkDeviceHost ASC)

**Максимальное время действия пароля не соответствует требованиям
(проверка по умолчанию):**

filter(NetworkDeviceHost) \| select(@NetworkDeviceHost,
NetworkDeviceHost.OsName as OsName,
NetworkDeviceHost.PasswordPolicy.Expiration.ExpirationPeriod as
ExpirationPeriod) \| filter(ExpirationPeriod = 0 or ExpirationPeriod \>
90) \| sort(@NetworkDeviceHost ASC)

**Максимальное время действия пароля не соответствует требованиям (Cisco
WLC):**

filter(WLCHost) \| select(@WLCHost, WLCHost.OsName as OsName,
WLCHost.PasswordPolicy\<OperatingSystem:Cisco:WLC:PasswordPolicy\>.UserClassSettings.UserClass
as UserClass,
WLCHost.PasswordPolicy\<OperatingSystem:Cisco:WLC:PasswordPolicy\>.UserClassSettings.ExpirationPeriod
as ExpirationPeriod) \| filter(not UserClass or ExpirationPeriod = 0 or
ExpirationPeriod \> 90) \| sort(@WLCHost ASC, UserClass ASC)

**Максимальное время действия пароля не соответствует требованиям (Palo
Alto):**

filter(PANHost) \| select(@PANHost, PANHost.OsName as OsName,
PANHost.User\<PaloAltoUser\>.Name as User,
PANHost.User\<PaloAltoUser\>.PasswordProfile as PasswordProfile) \|
join(select(@PANHost, PANHost.PasswordProfiles.Name as ProfileName,
PANHost.PasswordProfiles.ExpirationPeriod as ExpirationPeriod) as
Profiles, \@PANHost = Profiles.@PANHost and PasswordProfile =
Profiles.ProfileName) \| filter(not Profiles.ExpirationPeriod or
Profiles.ExpirationPeriod = 0 or Profiles.ExpirationPeriod \> 90) \|
select(@PANHost, OsName, User, PasswordProfile,
Profiles.ExpirationPeriod) \| sort(@PANHost ASC, User ASC)

**Количество сохраняемых паролей не соответствует требованиям (проверка
по умолчанию):**

filter(NetworkDeviceHost) \| select(@NetworkDeviceHost,
NetworkDeviceHost.OsName as OsName,
NetworkDeviceHost.PasswordPolicy.HistoryDepth as HistoryDepth) \|
filter(HistoryDepth \< 4) \| sort(@NetworkDeviceHost ASC)

**Не запрещено повторное использование паролей (FortiGate):**

filter(FortigateHost) \| select(@FortigateHost, FortigateHost.OsName,
FortigateHost.PasswordPolicy\<OperatingSystem:Fortinet:Fortios:PasswordPolicy\>.Status
as Status,
FortigateHost.PasswordPolicy\<OperatingSystem:Fortinet:Fortios:PasswordPolicy\>.AllowReuse
as AllowReuse) \| filter(Status = True and AllowReuse = True) \|
sort(@FortigateHost)

**Временная блокировка пользователей не соответствует требованиям
(проверка по умолчанию):**

filter(NetworkDeviceHost) \| select(@NetworkDeviceHost,
NetworkDeviceHost.OsName,
NetworkDeviceHost.PasswordPolicy.Lockout.Enabled as LockoutEnabled,
NetworkDeviceHost.PasswordPolicy.Lockout.Attempts as Attempts) \|
filter(LockoutEnabled = False or Attempts = 0 or Attempts \> 3) \|
sort(@NetworkDeviceHost ASC)

**Временная блокировка пользователей не соответствует требованиям (Cisco
WLC):**

filter(WLCHost) \| select(@WLCHost, WLCHost.OsName as OsName,
WLCHost.PasswordPolicy\<OperatingSystem:Cisco:WLC:PasswordPolicy\>.UserClassSettings.UserClass
as UserClass,
WLCHost.PasswordPolicy\<OperatingSystem:Cisco:WLC:PasswordPolicy\>.UserClassSettings.Lockout.Enabled
as LockoutEnabled,
WLCHost.PasswordPolicy\<OperatingSystem:Cisco:WLC:PasswordPolicy\>.UserClassSettings.Lockout.Attempts
as Attempts) \| filter(not UserClass or LockoutEnabled = False or
Attempts = 0 or Attempts \> 3) \| sort(@WLCHost ASC, UserClass ASC)

**Временная блокировка пользователей не соответствует требованиям (Palo
Alto):**

filter(PANHost) \| select(@PANHost, PANHost.OsName as OsName,
PANHost.User\<PaloAltoUser\>.Name as User,
PANHost.User\<PaloAltoUser\>.AuthenticationProfile as
AuthenticationProfile) \| join(select(@PANHost,
PANHost.AuthenticationProfiles.Name as ProfileName,
PANHost.AuthenticationProfiles.FailedAttempts as Attempts) as Profiles,
\@PANHost = Profiles.@PANHost and AuthenticationProfile =
Profiles.ProfileName) \| filter(not Profiles.Attempts or
Profiles.Attempts = 0 or Profiles.Attempts \> 3) \| select(@PANHost,
OsName, User, AuthenticationProfile, Profiles.Attempts) \| sort(@PANHost
ASC, User ASC)

**Парольная политика отключена (FortiGate):**

filter(FortigateHost.PasswordPolicy\<OperatingSystem:Fortinet:Fortios:PasswordPolicy\>.Status
= False or not
FortigateHost.PasswordPolicy\<OperatingSystem:Fortinet:Fortios:PasswordPolicy\>.ApplyTo
contains \'admin-password\') \| select(@FortigateHost,
FortigateHost.OsName,
FortigateHost.PasswordPolicy\<OperatingSystem:Fortinet:Fortios:PasswordPolicy\>.Status
as Status,
FortigateHost.PasswordPolicy\<OperatingSystem:Fortinet:Fortios:PasswordPolicy\>.ApplyTo
as ApplyTo) \| sort(@FortigateHost ASC, ApplyTo ASC)

**UNIX/LINUX.**

**Количество сохраняемых паролей не соответствует требованиям:**

filter(UnixHost.PasswordPolicy.PasswordHistory \< 12) \|
select(@UnixHost, UnixHost.OsName,
UnixHost.PasswordPolicy.PasswordHistory as PasswordHistory) \|
sort(@UnixHost ASC)

**Нестойкий алгоритм хеширования паролей:**

filter(not UnixHost.PasswordPolicy.Complexity.HashingAlgorithm in
\[\'sha512\', \'ssha512\', \'sha256\', \'ssha256\'\]) \|
select(@UnixHost, UnixHost.OsName,
UnixHost.PasswordPolicy.Complexity.HashingAlgorithm as HashingAlgorithm)
\| sort(@UnixHost ASC)

**Недостаточная длина пароля:**

filter(UnixHost.PasswordPolicy.Complexity.MinLen \< 8) \|
select(@UnixHost, UnixHost.OsName,
UnixHost.PasswordPolicy.Complexity.MinLen as Minlen,
UnixHost.PasswordPolicy.Complexity.MinClass as MinClass) \|
sort(@UnixHost ASC)

**Недостаточное количество различных символьных классов в пароле:**

filter(UnixHost.PasswordPolicy.Complexity.MinClass \< 3) \|
select(@UnixHost, UnixHost.OsName,
UnixHost.PasswordPolicy.Complexity.MinLen as Minlen,
UnixHost.PasswordPolicy.Complexity.MinClass as MinClass) \|
sort(@UnixHost ASC)

**Недостаточные требования к сроку действия паролей:**

filter(UnixHost) \| select(@UnixHost, UnixHost.OsName,
UnixHost.User\<UnixUser\>.Name as Name,
UnixHost.User\<UnixUser\>.PasswordMaxDays as PasswordMaxDays,
UnixHost.User\<UnixUser\>.PasswordMinDays as PasswordMinDays,
UnixHost.User\<UnixUser\>.PasswordIsSet as PasswordIsSet) \|
filter((PasswordMaxDays \> 90 or PasswordMinDays \< 1 or PasswordMaxDays
= 0) and PasswordIsSet = true) \| sort(@UnixHost, Name ASC)

**Опасные команды (SUDO):**

filter(UnixHost) \| select(@UnixHost, UnixHost.OsName as OsName,
UnixHost.Sudo.SudoConfig.UserSpecifications.Values.CmndSpecs.Cmnd as
Command) \| join(select(@UnixHost,
UnixHost.Sudo.SudoConfig.CmndAliases.Name as Name,
UnixHost.Sudo.SudoConfig.CmndAliases.Values as Value) as Alias,
\@UnixHost = Alias.@UnixHost and Alias.Name = Command) \|
select(@UnixHost, OsName, Command, Alias.Value as AliasCmd) \|
filter(AliasCmd match
\'\^\\s\*(?:/usr(?:/local)?)?(?:/s?bin/)?(?:find\|awk\|nmap\|vim?\|python\|irb\|less\|more\|man\|gdb\|ruby\|perl\|tee\|lua\|ftp\|sed\|dd)(?!\\S)\'
or Command match
\'\^\\s\*(?:/usr(?:/local)?)?(?:/s?bin/)?(?:find\|awk\|nmap\|vim?\|python\|irb\|less\|more\|man\|gdb\|ruby\|perl\|tee\|lua\|ftp\|sed\|dd)(?!\\S)\')
\| sort(@UnixHost, Command ASC)

**Разрешено выполнение любых команд от имени root:**

filter(UnixHost) \| select(@UnixHost, UnixHost.OsName as OsName,
UnixHost.Sudo.SudoConfig.UserSpecifications.Values.CmndSpecs.Cmnd as
Command,
UnixHost.Sudo.SudoConfig.UserSpecifications.Values.CmndSpecs.RunAsUsers
as AsUser,
UnixHost.Sudo.SudoConfig.UserSpecifications.Values.CmndSpecs.RunAsGroup
as AsGroup) \| filter(Command = \'ALL\' and (AsUser in \[\'ALL\',
\'root\'\] or AsGroup = \'ALL\')) \| unique() \| sort(@UnixHost, AsUser
ASC)

**Не установлен пароль для доступа к настройке загрузчика FreeBSD:**

filter(FreeBSDHost.Bootloader\<Loader\>.PasswordIsSet = False) \|
select(@FreeBSDHost, FreeBSDHost.OsName,
FreeBSDHost.Bootloader\<Loader\>.PasswordIsSet) \| sort(@FreeBSDHost
ASC)

**Не установлен пароль для доступа к настройке загрузчика GRUB:**

filter(UnixHost.Bootloader\<Grub\>\[not Users\]) \| select(@UnixHost,
UnixHost.OsName, UnixHost.Bootloader\<Grub\>.Users.Username as Username)
\| sort(@UnixHost ASC)

**Не настроена отправка сообщений syslog на удаленный сервер:**

filter(UnixHost.Daemons\<SyslogServer\>\[not Rules.Destination.Type =
\"remote\" or Autostart = False\]) \| select(@UnixHost, UnixHost.OsName,
UnixHost.Daemons\<SyslogServer\>.Name,
UnixHost.Daemons\<SyslogServer\>.Autostart as Autostart,
UnixHost.Daemons\<SyslogServer\>.Rules.Destination.Type as Destination)
\| unique() \| sort(@UnixHost ASC, UnixHost.Daemons\<SyslogServer\>.Name
ASC, Destination ASC)

**Автозапуск inetd:**

filter(UnixHost) \| select(@UnixHost, UnixHost.OsName,
UnixHost.Daemons.Name as Name, UnixHost.Daemons.Autostart as Autostart)
\| filter(Name like \"%inetd%\" and Autostart = True) \| sort(@UnixHost,
Name ASC)

**Автозапуск SMB и FTP:**

filter(UnixHost) \| select(@UnixHost, UnixHost.OsName,
UnixHost.Daemons.Name as Name, UnixHost.Daemons.Autostart as Autostart)
\| filter((Name in \[\"vsftpd\", \"/network/ftp:default\", \"smb\",
\"nmb\", \"smbd\", \"nmbd\", \"swat\", \"/network/smb/server:default\",
\"samba\", \"samba_server\"\]) and Autostart = True) \| sort(@UnixHost,
Name ASC)

**Автозапуск R-сервисов:**

filter(UnixHost) \| select(@UnixHost, UnixHost.OsName,
UnixHost.Daemons\<RServices\>.Name as Name,
UnixHost.Daemons\<RServices\>.AutoStart as Autostart) \|
filter(Autostart = True) \| sort(@UnixHost, Name ASC)

**Разрешен удаленный вход без указания пароля с помощью rlogin или
rsh:**

filter(UnixHost) \| select(@UnixHost, UnixHost.OsName,
UnixHost.Daemons\<RServices\>.Name as Name,
UnixHost.Daemons\<RServices\>.Nopasswd as NoPasswd) \| filter(NoPasswd
!= null) \| sort(@UnixHost, Name ASC)

**Пользователи с некорректными правами доступа к домашним каталогам:**

filter(UnixHost) \| select(@UnixHost as Host, UnixHost.OsName as OsName,
UnixHost.User\<UnixUser\>.HomeDirectory as Path,
UnixHost.User\<UnixUser\>.IsSystem as IsSystem,
UnixHost.User\<UnixUser\>.Name as Name, UnixHost.User\<UnixUser\>.id as
id) \| filter(IsSystem = False) \| join(select(@UnixHost as Host,
UnixHost.FileObjects.Path as Path, UnixHost.FileObjects.Permissions as
Permissions, UnixHost.FileObjects.Owner as Owner) as Q, Q.Host = Host
and Q.Path = Path) \| select(Host, OsName, Name, Path, Q.Owner as Owner,
Q.Permissions as Permissions) \| filter(Permissions !=
\'rwx\-\-\-\-\--\') \| sort(Host, Name ASC)

**Некорректные права доступа к исполняемым файлам и библиотекам ОС:**

filter(UnixHost) \| select(@UnixHost as Host, UnixHost.OsName as OsName,
UnixHost.FileObjects.Path as Path, UnixHost.FileObjects.Owner as Owner,
UnixHost.FileObjects.Permissions as Permissions) \| filter(Path match
\'\^(?:(?:/usr)?(?:/local)?(?:/s?bin/\\S+\|/lib(?:64\|exec)?/\\S+)\|/stand/\\S+\|/kernel/\\S+\|/platform/\\S+)\')
\| join(select(@UnixHost as Host, UnixHost.User\<UnixUser\>.Name as
Name, UnixHost.User\<UnixUser\>.IsSystem as IsSystem) as Q, Q.Host =
Host and Q.Name = Owner) \| select(Host, OsName, Path, Owner,
Permissions, Q.IsSystem as OwnerIsSystem) \| filter((OwnerIsSystem =
False and Owner != \'root\') or not Permissions match \'-..-.\$\') \|
sort(Host, Path ASC)

**Некорректные права доступа к файлам запущенных процессов:**

filter(UnixHost) \| select(@UnixHost as Host, UnixHost.OsName as OsName,
UnixHost.Processes.Name as Name, UnixHost.Processes.Path as Path) \|
join(select(@UnixHost as Host, UnixHost.FileObjects.Path as Path,
UnixHost.FileObjects.Permissions as Permissions) as Q, Q.Host = Host and
Q.Path = Path) \| unique() \| select(Host, OsName, Name, Path,
Q.Permissions as Permissions) \| filter(not Permissions match
\'-..-.\$\') \| sort(Host, Name ASC)

**Некорректные права доступа к файлу с пользователями:**

filter(UnixHost) \| select(@UnixHost, UnixHost.OsName,
UnixHost.FileObjects.Path, UnixHost.FileObjects.Permissions) \|
filter(UnixHost.FileObjects.Path = \'/etc/passwd\' and
UnixHost.FileObjects.Permissions !=\'rw-r\--r\--\') \| sort(@UnixHost
ASC)

**Некорректные права доступа к файлу с группами:**

filter(UnixHost) \| select(@UnixHost, UnixHost.OsName,
UnixHost.FileObjects.Path, UnixHost.FileObjects.Permissions) \|
filter(UnixHost.FileObjects.Path = \'/etc/group\' and
UnixHost.FileObjects.Permissions !=\'rw-r\--r\--\') \| sort(@UnixHost
ASC)

**Некорректные права доступа к файлам с битами SUID или SGID:**

filter(UnixHost) \| select(@UnixHost, UnixHost.OsName as OsName,
UnixHost.FileObjects.Path as Path, UnixHost.FileObjects.Permissions as
Permissions, UnixHost.FileObjects.Owner as Owner) \| filter(Permissions
match \'s\' and not Permissions match \'-..-.\$\') \| sort(@UnixHost,
Path ASC)

**Некорректные права доступа к сценариям, выполняющимся с помощью
cron:**

filter(UnixHost) \| select(@UnixHost, UnixHost.OsName,
UnixHost.FileObjects.Path as Path, UnixHost.FileObjects.Permissions as
Permissions) \| filter(Path match \'\^/(?:var/spool\|etc)/cron/.+\' and
Permissions match \'w.\$\') \| sort(@UnixHost ASC, Path ASC)

**Некорректные права доступа к стартовым сценариям:**

filter(UnixHost) \| select(@UnixHost as Host, UnixHost.OsName,
UnixHost.FileObjects.Path as Path, UnixHost.FileObjects.Permissions as
Permissions, UnixHost.FileObjects.Owner as Owner) \|
join(select(@UnixHost as Host, UnixHost.Daemons.Path as Path,
UnixHost.Daemons.Name as Name) as Startup, Host = Startup.Host and
Startup.Path = Path) \| filter(Startup.Path != null or Path match
\'\^/(?:etc/(?:rc\\d?\\.d\|init(?:\\.d)?)\|(?:etc\|lib)/systemd/system\|lib/svc/(?:method\|manifest))/\')
\| join(select(@UnixHost, UnixHost.User.Name as Name,
UnixHost.User.IsSystem as IsSystem) as User, Host=User.@UnixHost and
User.Name=Owner) \| select(Host, UnixHost.OsName, Path, Permissions,
Owner, User.IsSystem as OwnerIsSystem, Startup.Name as DaemonName) \|
filter((OwnerIsSystem = False and Owner != \'root\') or Permissions
match \'w.\$\') \| sort(Host, Path ASC)

**Пользователи с пустым паролем:**

filter(UnixHost) \| select(@UnixHost, UnixHost.OsName,
UnixHost.User\<UnixUser\>.Name as Name,
UnixHost.User\<UnixUser\>.PasswordNotEmpty,
UnixHost.User\<UnixUser\>.PasswordIsSet) \|
filter(UnixHost.User\<UnixUser\>.PasswordNotEmpty = False) \|
sort(@UnixHost, Name ASC)

**Пользователи с некорректным UID:**

filter(UnixHost) \| select(@UnixHost, UnixHost.OsName,
UnixHost.User\<UnixUser\>.Name as Name, UnixHost.User\<UnixUser\>.ID) \|
filter(UnixHost.User\<UnixUser\>.ID = \'0\' and Name != \'root\') \|
sort(@UnixHost, Name ASC)

**Пользователи с некорректными домашними каталогами:**

filter(UnixHost) \| select(@UnixHost, UnixHost.OsName,
UnixHost.User\<UnixUser\>.Name as Name,
UnixHost.User\<UnixUser\>.IsInteractive as IsInteractive,
UnixHost.User\<UnixUser\>.HomeDirectory as HomeDirectory) \|
filter(IsInteractive = True and (HomeDirectory = \'/\' or HomeDirectory
= \'\')) \| sort(@UnixHost, Name ASC)

**WINDOWS.**

**Установка ПО без уведомления пользователей(UAC):**

filter(WindowsHost.UserAccessControl.EnableInstallerDetection = False)
\| select(@WindowsHost, WindowsHost.OsName,
WindowsHost.UserAccessControl.EnableInstallerDetection) \|
sort(@WindowsHost ASC)

**Выключен контроль учетных записей (UAC):**

filter(WindowsHost.UserAccessControl.EnableLUA = False) \|
select(@WindowsHost, WindowsHost.OsName,
WindowsHost.UserAccessControl.EnableLUA) \| sort(@WindowsHost ASC)

**Путь службы содержит пробелы и не взят в кавычки:**

filter(WindowsHost) \| select(@WindowsHost, WindowsHost.OsName,
WindowsHost.Services.Name as Name, WindowsHost.Services.Path as Path) \|
filter(Path match \'\^(?!\[\\\'\"\])\\S+(?\<!\\.\\w+)\\s\') \|
sort(@WindowsHost ASC, Name ASC)

**Установка ПО с повышенными привилегиями:**

filter(WindowsHost.ComponentPolicies.AlwaysInstallElevated = True) \|
select(@WindowsHost, WindowsHost.OsName,
WindowsHost.ComponentPolicies.AlwaysInstallElevated) \|
sort(@WindowsHost ASC)

**Разрешен автозапуск устройств, не являющихся томами:**

filter(WindowsHost.ComponentPolicies.NoAutoplayfornonVolume = False) \|
select(@WindowsHost, WindowsHost.OsName,
WindowsHost.ComponentPolicies.NoAutoplayfornonVolume) \|
sort(@WindowsHost ASC)

**Разрешен автозапуск при подключении съемных носителей:**

filter(WindowsHost.ComponentPolicies.NoDriveTypeAutoRun != 255) \|
select(@WindowsHost, WindowsHost.OsName,
WindowsHost.ComponentPolicies.NoDriveTypeAutoRun) \| sort(@WindowsHost
ASC)

**Трансляция анонимного SID в имя:**

filter(WindowsHost.Lsa.LSAAnonymousNameLookup = True) \|
select(@WindowsHost, WindowsHost.OsName,
WindowsHost.Lsa.LSAAnonymousNameLookup) \| sort(@WindowsHost ASC)

**Анонимный доступ к общим сетевым ресурсам:**

filter(WindowsHost.LanmanServer\[NullSessionShares and
RestrictNullSessAccess = False\]) \| select(@WindowsHost,
WindowsHost.OsName, WindowsHost.LanmanServer.NullSessionShares as
NullSessionShares) \| sort(@WindowsHost ASC, NullSessionShares ASC)

**Анонимный доступ к именованным каналам:**

filter(WindowsHost.LanmanServer\[NullSessionPipes and
RestrictNullSessAccess = False\]) \| select(@WindowsHost,
WindowsHost.OsName, WindowsHost.LanmanServer.NullSessionPipes as
NullSessionPipes) \| sort(@WindowsHost ASC, NullSessionPipes ASC)

**Небезопасный уровень проверки подлинности LAN Manager:**

filter(WindowsHost.Lsa.LmCompatibilityLevel != 5) \|
select(@WindowsHost, WindowsHost.OsName,
WindowsHost.Lsa.LmCompatibilityLevel) \| sort(@WindowsHost ASC)

**Глубина парольной истории не соответствует требованиям:**

filter(WindowsHost.PasswordPolicy\[PasswordHistoryLength \< 12 or
PasswordHistoryLength \> 24\]) \| select(@WindowsHost,
WindowsHost.OsName, WindowsHost.PasswordPolicy.PasswordHistoryLength) \|
sort(@WindowsHost ASC)

**Минимальная длина пароля для рабочих станций не соответствует
требованиям:**

filter(WindowsHost\[PasswordPolicy.MinimumPasswordLength \< 8 and
InstallationType = \'Client\'\]) \| select(@WindowsHost,
WindowsHost.OsName, WindowsHost.PasswordPolicy.MinimumPasswordLength) \|
sort(@WindowsHost ASC)

**Минимальная длина пароля для серверов не соответствует требованиям:**

filter(WindowsHost\[PasswordPolicy.MinimumPasswordLength \< 14 and
InstallationType like \'%Server%\'\]) \| select(@WindowsHost,
WindowsHost.OsName, WindowsHost.PasswordPolicy.MinimumPasswordLength) \|
sort(@WindowsHost ASC)

**Срок действия пароля для рабочих станций не соответствует
требованиям:**

filter(WindowsHost\[(PasswordPolicy.MinimumPasswordAge \< 1 or
PasswordPolicy\[MaximumPasswordAge \> 60 or MaximumPasswordAge = 0\])
and InstallationType = \'Client\'\]) \| select(@WindowsHost,
WindowsHost.OsName, WindowsHost.PasswordPolicy.MinimumPasswordAge,
WindowsHost.PasswordPolicy.MaximumPasswordAge) \| sort(@WindowsHost ASC)

**Срок действия пароля для серверов не соответствует требованиям:**

filter(WindowsHost\[(PasswordPolicy.MinimumPasswordAge \< 1 or
PasswordPolicy\[MaximumPasswordAge \> 30 or MaximumPasswordAge = 0\])
and InstallationType like \'%Server%\'\]) \| select(@WindowsHost,
WindowsHost.OsName, WindowsHost.PasswordPolicy.MinimumPasswordAge,
WindowsHost.PasswordPolicy.MaximumPasswordAge) \| sort(@WindowsHost ASC)

**Не требуется пароль при выходе из спящего режима:**

filter(WindowsHost.PowerManagement\[ACSettingIndex = False or
DCSettingIndex = False\]) \| select(@WindowsHost, WindowsHost.OsName,
WindowsHost.PowerManagement.ACSettingIndex,
WindowsHost.PowerManagement.DCSettingIndex) \| sort(@WindowsHost ASC)

**Вход в систему без пароля:**

filter(WindowsHost.Lsa.AutoAdminLogon = True) \| select(@WindowsHost,
WindowsHost.OsName, WindowsHost.Lsa.AutoAdminLogon) \| sort(@WindowsHost
ASC)

**Список сетевых принтеров**

select(WindowsHost.Hostname, WindowsHost.Printers.Name,
WindowsHost.Printers.Location) \| filter(not
WindowsHost.Printers.Location = null) \|
sort(WindowsHost.Printers.Location ASC) \|
group(WindowsHost.Printers.Location, WindowsHost.Printers.Name)

**Cписок юсб устройств с указанием АРМ где они были**

select(WindowsHost.UsbDevices.Caption,
WindowsHost.UsbDevices.Description, WindowsHost.UsbDevices.DeviceID,
WindowsHost.UsbDevices.@Type, WindowsHost.Hostname) \|
filter(WindowsHost.UsbDevices.Description like \"%Storage%\" or
WindowsHost.UsbDevices.Description like \"%FC%\") \|
select(WindowsHost.Hostname, WindowsHost.UsbDevices.Description,
WindowsHost.UsbDevices.DeviceID) \|
group(WindowsHost.UsbDevices.DeviceID, COUNT(\*)) \| sort(\"COUNT(\*)\"
DESC)

**Группировка по сетям и IP-адресам на основании значения в
l3-interfaces**

select(Host.Interfaces.L3Settings.Address.Address.NetworkID as net,
Host.Interfaces.L3Settings.Address.Address.Address as addr) \|
group(net, COUNTUNIQUE(addr))

**Фильтрация по открытым tcp-портам**

filter(UnixHost.Endpoints\<TransportEndpoint\>\[Port in
\[554,2000,5060\] and Status = \"Open\" and Protocol = \"tcp\"\]) \|
select(@Host, Host.OsName, Host.@CreationTime, Host.@UpdateTime) \|
sort(@Host ASC)

host.@Vulners.Status = null -- не указана

host.@Vulners.Status = \'new\' -- новая

host.@Vulners.Status = \'excluded\' -- исключена

host.@Vulners.Status = \'inProgress\' -- в работе

host.@Vulners.Status = \'awaitingFix\' -- исправляется

host.@Vulners.Status = \'fixed\' -- устранена

host.@Vulners.Status = \'overdue\' - просрочена

host.@Vulners.Status = \'stale\' - требует проверки

select(@Host, Host.OsName, Host.@Vulners,
Host.@Vulners.VulnerableEntity.Name, Host.@Vulners.Status) \|
filter(Host.@Vulners.VulnerableEntity.Name = \'Jatoba\') \| group(@Host,
Host.@Vulners.Status, count(\*))

select(@Host, Host.OsName, Host.@Vulners,
Host.@Vulners.VulnerableEntity.Name, Host.@Vulners.Status,
Host.@Vulners.DueTime) \| filter(Host.@Vulners.VulnerableEntity.Name =
\'Jatoba\') \| group(@Host, Host.@Vulners.Status, count(\*))

Информация по процессорам для инвентаризации (отедльно вин\\лин)

select(@computer, computer.hostname as name, computer.OsName as OS,
computer.RAMSize as MEM, sum(computer.hdds.Size) as HDD,
computer.IpAddress as IP, computer.MacAddress as MAC,
countunique(computer.cpu.processornumber) as CPU,
computer.CPU\<WindowsCPU\>.NumberOfCores as CORE_WIN,
countunique(computer.cpu.processornumber) as CPU_LIN) \|
calc(CPU\*CORE_WIN as CPU_WIN) \| sort(CPU_LIN DESC)

Все известные сети

select(NetworkDeviceHost.RoutingTables.Routes.Destination.NetworkID as
NetID, NetworkDeviceHost.RoutingTables.Routes.Destination.Prefix as
NetPrefix) \| filter(NetID in \[10.0.0.0/8,192.168.0.0/16\] and
NetPrefix not in \[0,8,32\]) \| sort(NetID ASC) \| unique() \|
group(COUNT(NetID))

Дубли активов

filter(host.fqdn != \"null\") \| select(@Host, Host.OsName,
host.@AuditTime, host.Fqdn) \| group(host.Fqdn, COUNT(\*) as cnt) \|
filter(cnt \> 1)

filter(host.ipaddress != null and host.@audittime != null) \|
select(@Host, Host.OsName, host.@AuditTime, host.IpAddress) \|
group(host.IpAddress, COUNT(\*) as cnt) \| filter(cnt \> 1)

Уязвимости на портах
Host.Endpoints<TransportEndpoint>.Port, Host.Endpoints<TransportEndpoint>.Service.DisplayName , Host.Endpoints<TransportEndpoint>.@Vulners
