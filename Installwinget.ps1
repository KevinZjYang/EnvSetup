if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

function Check-Command($cmdname) {
    return [bool](Get-Command -Name $cmdname -ErrorAction SilentlyContinue)
}

function Remove-UWP {
    param (
        [string]$name
    )

    Write-Host "Removing UWP $name..." -ForegroundColor Yellow
    Get-AppxPackage $name | Remove-AppxPackage
    Get-AppxPackage $name | Remove-AppxPackage -AllUsers
}

Write-Host "OS Info:" -ForegroundColor Green
Get-CimInstance Win32_OperatingSystem | Format-List Name, Version, InstallDate, OSArchitecture
(Get-ItemProperty HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0\).ProcessorNameString
# -----------------------------------------------------------------------------
$computerName = Read-Host 'Enter New Computer Name'
Write-Host "Renaming this computer to: " $computerName  -ForegroundColor Yellow
Rename-Computer -NewName $computerName
# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "Disable Sleep on AC Power..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
Powercfg /Change monitor-timeout-ac 20
Powercfg /Change standby-timeout-ac 0
# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "Add 'This PC' Desktop Icon..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
$thisPCIconRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
$thisPCRegValname = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" 
$item = Get-ItemProperty -Path $thisPCIconRegPath -Name $thisPCRegValname -ErrorAction SilentlyContinue 
if ($item) { 
    Set-ItemProperty  -Path $thisPCIconRegPath -name $thisPCRegValname -Value 0  
} 
else { 
    New-ItemProperty -Path $thisPCIconRegPath -Name $thisPCRegValname -Value 0 -PropertyType DWORD | Out-Null  
} 

# To list all appx packages:
# Get-AppxPackage | Format-Table -Property Name,Version,PackageFullName
Write-Host "Removing UWP Rubbish..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
# $uwpRubbishApps = @(
#     "Microsoft.MSPaint"
#     "Microsoft.Microsoft3DViewer"
#     "Microsoft.ZuneMusic"
#     "Microsoft.ZuneVideo"
#     "*549981C3F5F10*"
#     "Microsoft.WindowsSoundRecorder"
#     "Microsoft.PowerAutomateDesktop"
#     "Microsoft.BingWeather"
#     "Microsoft.BingNews"
#     "king.com.CandyCrushSaga"
#     "Microsoft.Messaging"
#     "Microsoft.WindowsFeedbackHub"
#     "Microsoft.MicrosoftOfficeHub"
#     "Microsoft.MicrosoftSolitaireCollection"
#     "4DF9E0F8.Netflix"
#     "Microsoft.GetHelp"
#     "Microsoft.People"
#     "Microsoft.YourPhone"
#     "MicrosoftTeams"
#     "Microsoft.Getstarted"
#     "Microsoft.Microsoft3DViewer"
#     "Microsoft.WindowsMaps"
#     "Microsoft.MixedReality.Portal"
#     "Microsoft.SkypeApp")
$uwpRubbishApps = @(
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
    "*549981C3F5F10*"
    "Microsoft.WindowsSoundRecorder"
    "Microsoft.PowerAutomateDesktop"
    "Microsoft.BingWeather"
    "Microsoft.BingNews"
    "king.com.CandyCrushSaga"
    "Microsoft.Messaging"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.GetHelp"
    "Microsoft.People"
    "Microsoft.YourPhone"
    "MicrosoftTeams"
    "Microsoft.Getstarted"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.WindowsMaps"
    "Microsoft.MixedReality.Portal"
    "Microsoft.SkypeApp")

foreach ($uwp in $uwpRubbishApps) {
    Remove-UWP $uwp
}
# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "Starting UWP apps to upgrade..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
$namespaceName = "root\cimv2\mdm\dmmap"
$className = "MDM_EnterpriseModernAppManagement_AppManagement01"
$wmiObj = Get-WmiObject -Namespace $namespaceName -Class $className
$result = $wmiObj.UpdateScanMethod()

# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "Enable Windows 10 Developer Mode..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /t REG_DWORD /f /v "AllowDevelopmentWithoutDevLicense" /d "1"
# -----------------------------------------------------------------------------


Write-Host ""
Write-Host "Installing Applications..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
Write-Host "[WARN] Ma de in China: some software like Google Chrome require the true Internet first" -ForegroundColor Yellow

$Apps = @(
    "7zip.7zip",
    "voidtools.Everything",
    "GitHub.GitHubDesktop",
    "Microsoft.VisualStudioCode",
    "Nextcloud.NextcloudDesktop",
    "OBSProject.OBSStudio",
    "Microsoft.PowerToys",
    "Tencent.QQMusic",
    "Youqu.ToDesk",
    "Baidu.BaiduNetdisk",
    "Bilibili.Livehime",
    "Alibaba.DingTalk",
    "Tencent.WeSing",
    "Tencent.QQ",
    "Tencent.TencentMeeting",
    "Tencent.WeChat"
    )
# $Apps = @(
#     "wechat",
#     "tencentqq",
#     "tencentmeeting",
#     "everything",
#     "nextcloud-client",
#     "dingtalk",
#     "7zip.install",
#     "git",
#     "vscode",
#     "github-desktop",,
#     "obs-studio",
#     )

foreach ($app in $Apps) {
    winget install --id $app --silent
}

Write-Host "Setting up Git for Windows..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
git config --global user.email "yzj0308@hotmail.com"
git config --global user.name "KevinZjYang"
git config --global core.autocrlf true

Write-Host "Applying file explorer settings..." -ForegroundColor Green
cmd.exe /c "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v HideFileExt /t REG_DWORD /d 0 /f"
cmd.exe /c "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v AutoCheckSelect /t REG_DWORD /d 0 /f"
cmd.exe /c "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v LaunchTo /t REG_DWORD /d 1 /f"

Write-Host "Setting Time zone..." -ForegroundColor Green
Set-TimeZone -Name "China Standard Time"

# like %USERPROFILE%
# Write-Host "Excluding repos from Windows Defender..." -ForegroundColor Green
# Add-MpPreference -ExclusionPath "$env:USERPROFILE\source\repos"
# Add-MpPreference -ExclusionPath "$env:USERPROFILE\.nuget"
# Add-MpPreference -ExclusionPath "$env:USERPROFILE\.vscode"
# Add-MpPreference -ExclusionPath "$env:USERPROFILE\.dotnet"
# Add-MpPreference -ExclusionPath "$env:USERPROFILE\.ssh"
# Add-MpPreference -ExclusionPath "$env:APPDATA\npm"

# moonlight maybe get trouble.
Write-Host "Enabling Hardware-Accelerated GPU Scheduling..." -ForegroundColor Green
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\" -Name 'HwSchMode' -Value '2' -PropertyType DWORD -Force

# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "Checking Windows updates..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
Install-Module -Name PSWindowsUpdate -Force
Write-Host "Installing updates... (Computer will reboot in minutes...)" -ForegroundColor Green
Get-WindowsUpdate -AcceptAll -Install -ForceInstall -AutoReboot

# -----------------------------------------------------------------------------
Write-Host "------------------------------------" -ForegroundColor Green
Read-Host -Prompt "Setup is done, restart is needed, press [ENTER] to restart computer."
Restart-Computer
