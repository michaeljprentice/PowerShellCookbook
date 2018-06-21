<#
.Synopsis
   Deploy Powershell Module
.DESCRIPTION
   Long description
.EXAMPLE
   .\PublishToAent.ps1 -ReleaseNotes "This update fixes that odd problem"
#>
[CmdletBinding()]
[OutputType([string])]
Param
(
    # Param1 help description
    [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        Position = 0)]
    [string]$ReleaseNotes
)

$ModuleName = 'PowerShellCookBook'

$ModulePsdFile = "$($ModuleName).psd1"
$ModulePsdPath = "..\$ModulePsdFile"
$ModuleRootPath = "..\"

$PSGallery = 'AentPsGet'
$AentPSSite = 'https://psget.aent.com'
$SourceLocation = $AentPSSite + '/nuget'
$PublishLocation = $AentPSSite + '/api/v2/package'
$Gallery = Get-PSRepository -Name $PSGallery -ErrorAction SilentlyContinue
if (-Not $Gallery) {Register-PSRepository -Name $PSGallery -SourceLocation $SourceLocation -ScriptSourceLocation $SourceLocation -PublishLocation $PublishLocation -InstallationPolicy Trusted}

#Update-ModuleManifest -Path $Module -ReleaseNotes $ReleaseNotes
$TestModule = Test-ModuleManifest -Path $ModulePsdPath
$Version = $TestModule.Version
$newVersion = New-Object -TypeName System.Version -ArgumentList $Version.Major, $Version.Minor, $Version.Build, ($Version.Revision + 1)
Update-ModuleManifest -Path $ModulePsdPath -ModuleVersion $newVersion
Publish-Module -Path $ModuleRootPath -NuGetApiKey '8312A9B4-3788-4088-AE3C-B998A2CA665D' -Repository $PSGallery



#Command to create Manifest
function NewManafest() {
    # Conflict with Win10 Resolve-Error, Format-Hex, Get-Clipboard, New-SelfSignedCertificate, Send-MailMessage, Set-Clipboard

    New-ModuleManifest -Path .\PowerShellCookbookT.psd1 `
        -Guid '695122f6-fd0a-4869-9af1-c59f86310b1a' -Author 'Lee Holmes' `
        -CompanyName 'Lee Holmes' -Copyright '(c) 2009 Lee Holmes. All rights reserved.' `
        -RootModule 'PowerShellCookbook.psm1' -ModuleVersion '1.3.6' `
        -Description 'Sample scripts from the Windows PowerShell Cookbook' `
        -PowerShellVersion '3.0' -FunctionsToExport 'Add-ExtendedFileProperties', 'Add-FormatData', 
    'Add-FormatTableIndexParameter', 'Add-ObjectCollector', 
    'Add-RelativePathCapture', 'Compare-Property', 'Connect-WebService', 
    'ConvertFrom-FahrenheitWithFunction', 
    'ConvertFrom-FahrenheitWithoutFunction', 'Convert-TextObject', 
    'Copy-History', 'Enable-BreakOnError', 'Enable-HistoryPersistence', 
    'Enable-RemoteCredSSP', 'Enable-RemotePsRemoting', 'Enter-Module', 
    'Format-String', 'Get-AclMisconfiguration', 
    'Get-AliasSuggestion', 'Get-Answer', 'Get-Arguments', 
    'Get-Characteristics', 'Get-DetailedSystemInformation', 'Get-DiskUsage', 
    'Get-FacebookNotification', 'Get-FileEncoding', 
    'Get-InstalledSoftware', 'Get-InvocationInfo', 
    'Get-MachineStartupShutdownScript', 'Get-OfficialTime', 
    'Get-OperatingSystemSku', 'Get-OwnerReport', 'Get-PageUrls', 
    'Get-ParameterAlias', 'Get-PrivateProfileString', 
    'Get-RemoteRegistryChildItem', 'Get-RemoteRegistryKeyProperty', 
    'Get-ScriptCoverage', 'Get-ScriptPerformanceProfile', 'Get-Tomorrow', 
    'Get-UserLogonLogoffScript', 'Get-WarningsAndErrors', 
    'Get-WmiClassKeyProperty', 'Grant-RegistryAccessFullControl', 
    'Import-ADUser', 'Invoke-AddTypeTypeDefinition', 
    'Invoke-AdvancedFunction', 'Invoke-BinaryProcess', 'Invoke-CmdScript', 
    'Invoke-ComplexDebuggerScript', 'Invoke-ComplexScript', 
    'Invoke-DemonstrationScript', 'Invoke-ElevatedCommand', 
    'Invoke-Inline', 'Invoke-LocalizedScript', 
    'Invoke-LongRunningOperation,Invoke-Member', 
    'Invoke-RemoteExpression', 'Invoke-ScriptBlock', 
    'Invoke-ScriptBlockClosure', 'Invoke-ScriptThatRequiresMta', 
    'Invoke-SqlCommand', 'Invoke-WindowsApi', 
    'Measure-CommandPerformance', 'Move-LockedFile', 'New-CommandWrapper', 
    'New-DynamicVariable', 'New-FilesystemHardLink', 'New-GenericObject', 
    'New-ZipFile', 'Read-HostWithPrompt', 
    'Read-InputBox', 'Register-TemporaryEvent',  
    'Search-Bing', 'Search-CertificateStore', 'Search-Help', 
    'Search-Registry', 'Search-StackOverflow', 'Search-StartMenu', 
    'Search-WmiNamespace', 'Select-FilteredObject', 
    'Select-GraphicalFilteredObject', 'Select-TextOutput', 'Send-File', 
    'Send-TcpRequest', 'Set-ConsoleProperties', 'Set-PsBreakPointLastError', 
    'Set-RemoteRegistryKeyProperty', 'Show-ColorizedContent', 
    'Show-Object', 'Start-ProcessAsUser', 'Test-Uri', 'Use-Culture', 
    'Watch-Command', 'Watch-DebugExpression'

}