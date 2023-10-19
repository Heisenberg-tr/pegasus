import os

def disable_telemetry():
    os.system(r'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f')
    os.system(r'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowDeviceNameInTelemetry /t REG_DWORD /d 0 /f')
    os.system(r'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v PreventHandwritingDataSharing /t REG_DWORD /d 0 /f')
    os.system(r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack" /v Start /t REG_DWORD /d 4 /f')
    os.system(r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagsvc" /v Start /t REG_DWORD /d 4 /f')
    os.system(r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v Start /t REG_DWORD /d 4 /f')
    os.system(r'reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f')
    os.system(r'reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f')
    os.system(r'reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\SQMClient\Windows" /v CEIPEnable /t REG_DWORD /d 0 /f')
    os.system(r'reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f')



def improve_startup():
    execute_commands=[
        r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AxInstSV" /v Start /t REG_DWORD /d 3 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppMgmt" /v Start /t REG_DWORD /d 3 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertPropSvc" /v Start /t REG_DWORD /d 3 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PeerDistSvc" /v Start /t REG_DWORD /d 3 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SCPolicySvc" /v Start /t REG_DWORD /d 3 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMPTRAP" /v Start /t REG_DWORD /d 3 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WebClient" /v Start /t REG_DWORD /d 3 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM" /v Start /t REG_DWORD /d 3 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WerSvc" /v Start /t REG_DWORD /d 3 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNRPsvc" /v Start /t REG_DWORD /d 3 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\p2psvc" /v Start /t REG_DWORD /d 3 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\p2pimsvc" /v Start /t REG_DWORD /d 3 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysMain" /v DelayedAutoStart /t REG_DWORD /d 1 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /f',
        r'bcdedit /timeout 6'
    ]
    for i in execute_commands:
        os.system(i)

def disable_autoupdate():
    execute_commands = [
        r'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AutoInstallMinorUpdates /t REG_DWORD /d 0 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore" /v AutoDownload /t REG_DWORD /d 2 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v SetAutoRestartNotificationDisable /t REG_DWORD /d 1 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Maps" /v AutoDownloadAndUpdateMapData /t REG_DWORD /d 0 /f'
    ]
    for i in execute_commands:
        os.system(i)

def disable_throttling():
    execute_commands = [
        r'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 4294967295 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched" /v TimerResolution /t REG_DWORD /d 0 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched" /v NonBestEffortLimit /t REG_DWORD /d 0 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" /v explorer.exe /t REG_DWORD /d 10 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" /v explorer.exe /t REG_DWORD /d 10 /f'
    ]
    for i in execute_commands:
        os.system(i)

def disable_services():
    execute_commands = [
        r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v LocalPriority /t REG_DWORD /d 4 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v HostsPriority /t REG_DWORD /d 5 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v DnsPriority /t REG_DWORD /d 6 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v NetbtPriority /t REG_DWORD /d 7 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /t REG_SZ /d "1" /f',
        r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v Size /t REG_DWORD /d 3 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v MaxUserPort /t REG_DWORD /d 65534 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpTimedWaitDelay /t REG_DWORD /d 30 /f',
        r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DefaultTTL /t REG_DWORD /d 64 /f'
    ]
    for i in execute_commands:
        os.system(i)

def configure_adapter():
    execute_commands = [
        r'powershell Set-NetTCPSetting -SettingName internet -AutoTuningLevelLocal normal',
        r'powershell Set-NetTCPSetting -SettingName internet -ScalingHeuristics disabled',
        r'netsh int tcp set supplemental internet congestionprovider=CUBIC',
        r'powershell Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing disabled',
        r'powershell Set-NetOffloadGlobalSetting -ReceiveSideScaling enabled',
        r'powershell Disable-NetAdapterLso -Name *',
        r'powershell Enable-NetAdapterChecksumOffload -Name *',
        r'powershell Set-NetTCPSetting -SettingName internet -EcnCapability disabled',
        r'powershell Set-NetOffloadGlobalSetting -Chimney disabled',
        r'powershell Set-NetTCPSetting -SettingName internet -Timestamps disabled',
        r'powershell Set-NetTCPSetting -SettingName internet -MaxSynRetransmissions 2',
        r'powershell Set-NetTCPSetting -SettingName internet -NonSackRttResiliency disabled',
        r'powershell Set-NetTCPSetting -SettingName internet -InitialRto 2000',
        r'powershell Set-NetTCPSetting -SettingName internet -MinRto 300',
        r'netsh interface ipv4 set subinterface Ethernet mtu=1500 store=persistent',
        r'netsh interface ipv6 set subinterface Ethernet mtu=1500 store=persistent',
        r'netsh interface ipv4 set subinterface Wi-Fi mtu=1500 store=persistent',
        r'netsh interface ipv6 set subinterface Wi-Fi mtu=1500 store=persistent'
    ]
    for i in execute_commands:
        os.system(i)

