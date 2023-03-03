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

# if (Check-Command -cmdname 'choco') {
#     Write-Host "Choco is already installed, skip installation."
# }
# else {
#     Write-Host ""
#     Write-Host "Installing Chocolate for Windows..." -ForegroundColor Green
#     Write-Host "------------------------------------" -ForegroundColor Green
#     Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
# }

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
    winget.exe install $app -h
}

