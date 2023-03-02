if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

function Check-Command($cmdname) {
    return [bool](Get-Command -Name $cmdname -ErrorAction SilentlyContinue)
}

function AddToPath {
    param (
        [string]$folder
    )

    Write-Host "Adding $folder to environment variables..." -ForegroundColor Yellow

    $currentEnv = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine).Trim(";");
    $addedEnv = $currentEnv + ";$folder"
    $trimmedEnv = (($addedEnv.Split(';') | Select-Object -Unique) -join ";").Trim(";")
    [Environment]::SetEnvironmentVariable(
        "Path",
        $trimmedEnv,
        [EnvironmentVariableTarget]::Machine)

    #Write-Host "Reloading environment variables..." -ForegroundColor Green
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}

function Remove-UWP {
    param (
        [string]$name
    )

    Write-Host "Removing UWP $name..." -ForegroundColor Yellow
    Get-AppxPackage $name | Remove-AppxPackage
    Get-AppxPackage $name | Remove-AppxPackage -AllUsers
}

# 输出系统信息
Write-Host "OS Info:" -ForegroundColor Green
Get-CimInstance Win32_OperatingSystem | Format-List Name, Version, InstallDate, OSArchitecture
(Get-ItemProperty HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0\).ProcessorNameString
# -----------------------------------------------------------------------------
# 重命名电脑名称
$computerName = Read-Host 'Enter New Computer Name'
Write-Host "Renaming this computer to: " $computerName  -ForegroundColor Yellow
Rename-Computer -NewName $computerName
# -----------------------------------------------------------------------------
# 关掉电脑睡眠,防止安装过程停止
Write-Host ""
Write-Host "Disable Sleep on AC Power..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
Powercfg /Change monitor-timeout-ac 20
Powercfg /Change standby-timeout-ac 0
# -----------------------------------------------------------------------------
# 桌面添加我的电脑图标
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
# 删除无用的UWP应用
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
# 更新UWP
# Write-Host ""
# Write-Host "Starting UWP apps to upgrade..." -ForegroundColor Green
# Write-Host "------------------------------------" -ForegroundColor Green
# $namespaceName = "root\cimv2\mdm\dmmap"
# $className = "MDM_EnterpriseModernAppManagement_AppManagement01"
# $wmiObj = Get-WmiObject -Namespace $namespaceName -Class $className
# $result = $wmiObj.UpdateScanMethod()
# -----------------------------------------------------------------------------
# Write-Host ""
# Write-Host "Installing IIS..." -ForegroundColor Green
# Write-Host "------------------------------------" -ForegroundColor Green
# Enable-WindowsOptionalFeature -Online -FeatureName IIS-DefaultDocument -All
# Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpCompressionDynamic -All
# Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpCompressionStatic -All
# Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebSockets -All
# Enable-WindowsOptionalFeature -Online -FeatureName IIS-ApplicationInit -All
# Enable-WindowsOptionalFeature -Online -FeatureName IIS-ASPNET45 -All
# Enable-WindowsOptionalFeature -Online -FeatureName IIS-ServerSideIncludes
# Enable-WindowsOptionalFeature -Online -FeatureName IIS-BasicAuthentication
# Enable-WindowsOptionalFeature -Online -FeatureName IIS-WindowsAuthentication
# -----------------------------------------------------------------------------
# 打开开发人员模式
Write-Host ""
Write-Host "Enable Windows 10 Developer Mode..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /t REG_DWORD /f /v "AllowDevelopmentWithoutDevLicense" /d "1"
# -----------------------------------------------------------------------------
# 启用远程桌面
# Write-Host ""
# Write-Host "Enable Remote Desktop..." -ForegroundColor Green
# Write-Host "------------------------------------" -ForegroundColor Green
# Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\" -Name "fDenyTSConnections" -Value 0
# Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\" -Name "UserAuthentication" -Value 1
# Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# 安装choco,并安装必装应用
if (Check-Command -cmdname 'choco') {
    Write-Host "Choco is already installed, skip installation."
}
else {
    Write-Host ""
    Write-Host "Installing Chocolate for Windows..." -ForegroundColor Green
    Write-Host "------------------------------------" -ForegroundColor Green
    Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}

Write-Host ""
Write-Host "Installing Applications..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
Write-Host "[WARN] Ma de in China: some software like Google Chrome require the true Internet first" -ForegroundColor Yellow

$Apps = @(
    "wechat",
    "tencentqq",
    "tencentmeeting"
    )

foreach ($app in $Apps) {
    choco install $app -y
}

# gsudo
# PowerShell -Command "Set-ExecutionPolicy RemoteSigned -scope Process; [Net.ServicePointManager]::SecurityProtocol = 'Tls12'; iwr -useb https://raw.githubusercontent.com/gerardog/gsudo/master/installgsudo.ps1 | iex"

# Write-Host "Setting up Git for Windows..." -ForegroundColor Green
# Write-Host "------------------------------------" -ForegroundColor Green
# git config --global user.email "edi.wang@outlook.com"
# git config --global user.name "Edi Wang"
# git config --global core.autocrlf true


#aria2
# if ($true)
# {
#     Write-Host "Installing aria2 as download tool..." -ForegroundColor Green
#     Write-Host "------------------------------------" -ForegroundColor Green
#     $downloadAddress = "https://github.com/aria2/aria2/releases/download/release-1.36.0/aria2-1.36.0-win-64bit-build1.zip"
#     Invoke-WebRequest $downloadAddress -OutFile "$HOME\aria2.zip"
#     $installPath = "${env:ProgramFiles}\aria2"
#     & "${env:ProgramFiles}\7-Zip\7z.exe" x "$HOME\aria2.zip" "-o$($installPath)" -y
#     $subPath = $(Get-ChildItem -Path $installPath | Where-Object { $_.Name -like "aria2-*" } | Sort-Object Name -Descending | Select-Object -First 1).Name
#     $subPath = Join-Path -Path $installPath -ChildPath $subPath
#     Remove-Item $installPath\aria2c.exe -ErrorAction SilentlyContinue
#     Move-Item $subPath\aria2c.exe $installPath
#     AddToPath -folder $installPath
#     Remove-Item -Path "$HOME\aria2.zip" -Force
# }

# Chromium,edge很好用啊
# if ($true) { 
#     Write-Host "Installing Chromium as backup browser (For second Teams\AAD usage)..." -ForegroundColor Green
#     Write-Host "------------------------------------" -ForegroundColor Green
#     $chromiumUrl = "https://download-chromium.appspot.com/dl/Win_x64?type=snapshots"
#     $chromiumPath = "${env:ProgramFiles}\Chromium"
    
#     $downloadedChromium = $env:USERPROFILE + "\chrome-win.zip"
#     Remove-Item $downloadedChromium -ErrorAction SilentlyContinue
#     aria2c.exe $chromiumUrl -d $HOME -o "chrome-win.zip"
    
#     & "${env:ProgramFiles}\7-Zip\7z.exe" x $downloadedChromium "-o$($chromiumPath)" -y
    
#     $shortCutPath = $env:USERPROFILE + "\Start Menu\Programs" + "\Chromium.lnk"
#     Remove-Item -Path $shortCutPath -Force -ErrorAction SilentlyContinue
#     $objShell = New-Object -ComObject ("WScript.Shell")
#     $objShortCut = $objShell.CreateShortcut($shortCutPath)
#     $objShortCut.TargetPath = "$chromiumPath\chrome-win\Chrome.exe"
#     $objShortCut.Save()

#     Remove-Item -Path $downloadedChromium -Force
# }

# Android CLI
# if ($true) {
#     Write-Host "Downloading Android-Platform-Tools (To connect to Android Phone)..." -ForegroundColor Green
#     Write-Host "------------------------------------" -ForegroundColor Green
#     $toolsPath = "${env:ProgramFiles}\Android-Platform-Tools"
#     $downloadUri = "https://dl.google.com/android/repository/platform-tools-latest-windows.zip"
    
#     $downloadedTool = $env:USERPROFILE + "\platform-tools-latest-windows.zip"
#     Remove-Item $downloadedTool -ErrorAction SilentlyContinue
#     aria2c.exe $downloadUri -d $HOME -o "platform-tools-latest-windows.zip"
    
#     & ${env:ProgramFiles}\7-Zip\7z.exe x $downloadedTool "-o$($toolsPath)" -y
#     AddToPath -folder "$toolsPath\platform-tools"
#     Remove-Item -Path $downloadedTool -Force
# }

# FFmpeg
# if ($true) {
#     Write-Host "Downloading FFmpeg..." -ForegroundColor Green
#     Write-Host "------------------------------------" -ForegroundColor Green
#     $ffmpegPath = "${env:ProgramFiles}\FFMPEG"
#     $downloadUri = "https://www.gyan.dev/ffmpeg/builds/ffmpeg-git-full.7z"
    
#     $downloadedFfmpeg = $env:USERPROFILE + "\ffmpeg-git-full.7z"
#     Remove-Item $downloadedFfmpeg -ErrorAction SilentlyContinue
#     aria2c.exe $downloadUri -d $HOME -o "ffmpeg-git-full.7z"

#     & ${env:ProgramFiles}\7-Zip\7z.exe x $downloadedFfmpeg "-o$($ffmpegPath)" -y
#     $subPath = $(Get-ChildItem -Path $ffmpegPath | Where-Object { $_.Name -like "ffmpeg*" } | Sort-Object Name -Descending | Select-Object -First 1).Name
#     $subPath = Join-Path -Path $ffmpegPath -ChildPath $subPath
#     $binPath = Join-Path -Path $subPath -ChildPath "bin"
#     Remove-Item $ffmpegPath\*.exe
#     Move-Item $binPath\*.exe $ffmpegPath

#     Write-Host "Adding FFmpeg to PATH..." -ForegroundColor Green
#     AddToPath -folder $ffmpegPath
#     Remove-Item -Path $downloadedFfmpeg -Force
# }

# Kubernetes CLI
# if ($true) {
#     Write-Host "Downloading Kubernetes CLI..." -ForegroundColor Green
#     Write-Host "------------------------------------" -ForegroundColor Green
#     $toolsPath = "${env:ProgramFiles}\Kubernetes"
#     $downloadUri = "https://dl.k8s.io/release/v1.25.0/bin/windows/amd64/kubectl.exe"
    
#     $downloadedTool = $env:USERPROFILE + "\kubectl.exe"
#     Remove-Item $downloadedTool -ErrorAction SilentlyContinue
#     aria2c.exe $downloadUri -d $HOME -o "kubectl.exe"
    
#     New-Item -Type Directory -Path "${env:ProgramFiles}\Kubernetes" -ErrorAction SilentlyContinue
#     Move-Item $downloadedTool "$toolsPath\kubectl.exe" -Force
#     AddToPath -folder $toolsPath
# }

# wget
# if ($true) {
#     Write-Host "Downloading Wget because some app may need it..." -ForegroundColor Green
#     Write-Host "------------------------------------" -ForegroundColor Green
#     $wgetPath = "${env:ProgramFiles}\wget"
#     $downloadUri = "https://eternallybored.org/misc/wget/releases/wget-1.21.3-win64.zip"
#     $downloadedWget = $env:USERPROFILE + "\wget-1.21.3-win64.zip"
#     Remove-Item $downloadedWget -ErrorAction SilentlyContinue
#     aria2c.exe $downloadUri -d $HOME -o "wget-1.21.3-win64.zip"
    
#     & ${env:ProgramFiles}\7-Zip\7z.exe x $downloadedWget "-o$($wgetPath)" -y
#     Write-Host "Adding wget to PATH..." -ForegroundColor Green
#     AddToPath -folder $wgetPath
#     Remove-Item -Path $downloadedWget -Force
# }

# Write-Host "Setting up dotnet for Windows..." -ForegroundColor Green
# Write-Host "------------------------------------" -ForegroundColor Green
# [Environment]::SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Development", "Machine")
# [Environment]::SetEnvironmentVariable("DOTNET_PRINT_TELEMETRY_MESSAGE", "false", "Machine")
# [Environment]::SetEnvironmentVariable("DOTNET_CLI_TELEMETRY_OPTOUT", "1", "Machine")
# dotnet tool install --global dotnet-ef
# dotnet tool update --global dotnet-ef

# Write-Host "Enabling Chinese input method..." -ForegroundColor Green
# Write-Host "------------------------------------" -ForegroundColor Green
# $LanguageList = Get-WinUserLanguageList
# $LanguageList.Add("zh-CN")
# Set-WinUserLanguageList $LanguageList -Force

# 文件资源管理器设置
Write-Host "Applying file explorer settings..." -ForegroundColor Green
cmd.exe /c "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v HideFileExt /t REG_DWORD /d 0 /f"
cmd.exe /c "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v AutoCheckSelect /t REG_DWORD /d 0 /f"
cmd.exe /c "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v LaunchTo /t REG_DWORD /d 1 /f"

# 设置时区
Write-Host "Setting Time zone..." -ForegroundColor Green
Set-TimeZone -Name "China Standard Time"

# 从Windows defender中排除这些文件夹;"USERPROFILE"用户文件夹,等同于%USERPROFILE%
# Write-Host "Excluding repos from Windows Defender..." -ForegroundColor Green
# Add-MpPreference -ExclusionPath "$env:USERPROFILE\source\repos"
# Add-MpPreference -ExclusionPath "$env:USERPROFILE\.nuget"
# Add-MpPreference -ExclusionPath "$env:USERPROFILE\.vscode"
# Add-MpPreference -ExclusionPath "$env:USERPROFILE\.dotnet"
# Add-MpPreference -ExclusionPath "$env:USERPROFILE\.ssh"
# Add-MpPreference -ExclusionPath "$env:APPDATA\npm"

# 开启硬件加速GPU计划,一般系统默认开启的.备注:开启后使用moonlight串流可能导致画面卡住,声音还在.
# Write-Host "Enabling Hardware-Accelerated GPU Scheduling..." -ForegroundColor Green
# New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\" -Name 'HwSchMode' -Value '2' -PropertyType DWORD -Force

# Azure开发使用,用不到
# Write-Host "Installing Github.com/microsoft/artifacts-credprovider..." -ForegroundColor Green
# Write-Host "------------------------------------" -ForegroundColor Green
# Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/microsoft/artifacts-credprovider/master/helpers/installcredprovider.ps1'))

# 不理解为啥要删除
# Write-Host "Removing Bluetooth icons..." -ForegroundColor Green
# Write-Host "------------------------------------" -ForegroundColor Green
# cmd.exe /c "reg add `"HKCU\Control Panel\Bluetooth`" /v `"Notification Area Icon`" /t REG_DWORD /d 0 /f"

# -----------------------------------------------------------------------------
# 检查Windows更新,安装后重启
# Write-Host ""
# Write-Host "Checking Windows updates..." -ForegroundColor Green
# Write-Host "------------------------------------" -ForegroundColor Green
# Install-Module -Name PSWindowsUpdate -Force
# Write-Host "Installing updates... (Computer will reboot in minutes...)" -ForegroundColor Green
# Get-WindowsUpdate -AcceptAll -Install -ForceInstall -AutoReboot

# -----------------------------------------------------------------------------
# 重启计算机
# Write-Host "------------------------------------" -ForegroundColor Green
# Read-Host -Prompt "Setup is done, restart is needed, press [ENTER] to restart computer."
# Restart-Computer
