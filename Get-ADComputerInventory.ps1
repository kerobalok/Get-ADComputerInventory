#region Documentation
<#
.Synopsis
Ble ble ble
.Description
This script reads computer accounts with MS Windows OS from Active Directory Organization Unit and scan them for processor, OS Version, RAM etc.
.Notes
AUTHOR: Daniel Sajdyk


.Link
http://
#Requires-Version ??????
#>
#endregion

#region Variables
$OUPath = "OU=5039,OU=Rejon,OU=Resort,DC=ad,DC=ms,DC=gov,DC=pl"
#$computersFromOU = ("5039-marnow-k.ad.ms.gov.pl","slebd01.ad.ms.gov.pl")
$resultsFile = "scannedComputers.csv"
#endregion

#region Testing Credentials and if ther're correct getting computer DNSHostnames list from AD into $computersFromOU variable
try {
    $computersFromOU = (Get-ADComputer -Credential $credentials -SearchBase $OUPath -Filter * -Properties OperatingSystem, OperatingSystemServicePack, OperatingSystemVersion, WhenCreated -ErrorAction Stop | Where-Object {($_.OperatingSystem -like "*windows*") -and ($_.Enabled -eq $TRUE)}).DNSHostName
}
catch {
    $somethingWentWrong = $_
    if ($somethingWentWrong.Exception.Message -like "*Get-ADComputer*"){
        Write-Warning -Message "W sytemie brakuje commandletu 'Get-ADComputer', a to prawdopodobnie znaczy brak modulu ActiveDirectory. Zainstalowane moduly mozesz sprawdzic poleceniem 'Get-Module'. Ponizej systemowy opis bledu"
        Throw
    }
    else {
        Throw
    }
}
#endregion


#region Checking if file with reults from previous scans exist and if so, skipping computers included in that file (they were already scanned).
$computersToScan = @()
if ($TRUE -eq (Test-Path -LiteralPath $resultsFile)){
    $alreadyScannedComputers = Import-Csv -Path $resultsFile -delimiter ";"
    ForEach ($computerFromOU in $computersFromOU){
        if ( ($alreadyScannedComputers.PSComputerName -notcontains $computerFromOU) -and ($alreadyScannedComputers.PhysicalHostname -notcontains $computerFromOU) ) {
            $computersToScan += $computerFromOU
        }
    }
}
else {
    $computersToScan = $computersFromOU
}
Remove-Variable alreadyScannedComputers
#endregion


#region Scanning section
# if variable $computersToScan exists, it means that there are no scan results in file $resultsFile and that means, that those computers wasn't scanned before
#      ......... zrobić sprawdzanie nie czy istnieje zmienna computersToScan, ale czy istnieje i czy jest typu... ustalić jakiego typu.......
if ($TRUE -eq $computersToScan) { 
    $sessions = New-PSSession -ComputerName $computersToScan -ErrorAction SilentlyContinue -Credential $credentials

    if ($TRUE -eq $sessions) {
        $results = Invoke-Command -Session $sessions -ScriptBlock {

            # Code for PowerShell with major version greater than 5
            if (($PSVersionTable.PSVersion.Major) -ge 5) {
                $Win32_ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -property *
                $Win32_Processor = Get-CimInstance -ClassName Win32_Processor -property *
                $Win32_SystemEnclosure = Get-CimInstance -ClassName Win32_SystemEnclosure -property *
                $Win32_DiskDrive = Get-CimInstance -ClassName Win32_DiskDrive -property *
                $OS = ((Get-CimInstance Win32_OperatingSystem -Property *).Name.Split("|") | Select-Object -First 1)
                #$IPAddress = (Get-NetConnectionProfile).InterfaceIndex | Get-NetIPAddress -InterfaceIndex {($_)} | Where-Object {$_.AddressFamily -like "IPv4"};
                $IPAddress = ((Get-NetConnectionProfile).InterfaceIndex | Get-NetIPAddress -InterfaceIndex {($_)} | Where-Object {$_.AddressFamily -like "IPv4"} | foreach-object {"(" + ($_.SuffixOrigin) + ": " + (($_.IPAddress).ToString()) + ": " + ((Get-NetAdapter -InterfaceIndex $_.InterfaceIndex).MacAddress) + ")"})

                $tablica = @{}
                $tablica.add("ScanDate",             (Get-Date -DisplayHint Date)) #Get-Date -Format {dd.MM.yyyy}
                $tablica.add("PhysicalHostname",     ([System.Net.Dns]::GetHostByName($env:computerName)).HOSTNAME) #Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -Property {$_.Name + "." + $_.Domain}
                $tablica.add("Manufacturer",         $Win32_ComputerSystem.Manufacturer)
                $tablica.add("Model",                $Win32_ComputerSystem.Model)
                $tablica.add("ComputerSerialNumber", $Win32_SystemEnclosure.SerialNumber)
                $tablica.add("ProcessorName",        (($Win32_Processor.Name) | Get-Unique)) #Get-Ciminstance -Query 'SELECT Name FROM Win32_Processor'
                $tablica.add("NrOfProcessors",       ($Win32_Processor.Name).Count)
                $tablica.add("RAM",                  ([math]::Round(($Win32_ComputerSystem.TotalPhysicalMemory / 1GB),2)))
                $tablica.add("DiskDrive",            ($Win32_DiskDrive.Size | ForEach-Object {[math]::Round(($_ / 1GB),2)}) )
                #$tablica.add("HDDPartitions",        (Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3").Size   )
                #HDDPartitions = (Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3").Size | ForEach-Object {[math]::Round(($_ / 1GB),2)};
                $tablica.add("OS",                   $OS)
                #$tablica.add("LocalAccounts",       (get-localuser | foreach {if($_.Enabled -eq $true){$_.Name + "`(A`)"}else{$_.Name +"`(D`)"}}))
                $tablica.add("LocalAdministrators",  (Get-LocalGroupMember -SID S-1-5-32-544))
                $tablica.add("IPaddress",             $IPAddress)
                #$tablica.add("IPAddress",            $IPAddress.IPAddress)
                #$tablica.add("SuffixOrigin",         $IPAddress.SuffixOrigin)
                $tablica.add("PSVersion",           (($PSVersionTable.PSVersion.Major).ToString() + "." + ($PSVersionTable.PSVersion.Minor)))
                
                new-object -Type psobject -Property $tablica
            }

            # Code for PowerShell with major version less than 5
            else {
                $Win32_ComputerSystem = Get-WmiObject -Class Win32_ComputerSystem
                $Win32_Processor = Get-WmiObject -Class Win32_Processor
                $Win32_DiskDrive = Get-WmiObject -Class Win32_DiskDrive
                $OS = &{$x = get-wmiobject win32_operatingsystem | Select-Object -ExpandProperty Name; $x.split("|")[0]}

                $tablica = @{}
                $tablica.add("ScanDate",            (Get-Date -DisplayHint Date))
                $tablica.add("PhysicalHostname",    ([System.Net.Dns]::GetHostByName($env:computerName)).HOSTNAME) #($env:computername + "." + $env:USERDNSDOMAIN);
                $tablica.add("Manufacturer",        $Win32_ComputerSystem.Manufacturer)
                $tablica.add("Model",               $Win32_ComputerSystem.Model)
                $tablica.add("ComputerSerialNumber",$NULL)
                $tablica.add("ProcessorName",       $Win32_Processor.Name)
                $tablica.add("NrOfProcessors",      ($Win32_Processor | Measure-Object | Select-Object -ExpandProperty Count))
                $tablica.add("RAM",                 ([math]::Round(($Win32_ComputerSystem.TotalPhysicalMemory / 1GB),2)))
                $tablica.add("DiskDrive",           ($Win32_DiskDrive.Size | ForEach-Object {[math]::Round(($_ / 1GB),2)}) )
                #$tablica.add("HDDPartitions",      $NULL)
                $tablica.add("OS",                  $OS)   
                $tablica.add("LocalAdministrators", $NULL)
                $tablica.add("IPAddress",           $NULL)
                #$tablica.add("SuffixOrigin",        $NULL)
                $tablica.add("PSVersion",           (($PSVersionTable.PSVersion.Major).ToString() + "." + ($PSVersionTable.PSVersion.Minor)))
                

                new-object -Type PSobject -Property $tablica
            }
        }
    
                

        # Saving results to a file
        $results | select-object -property              `
                                "ScanDate",             `
                                "PSComputerName",       `
                                #"LogicalHostname",     `
                                "PhysicalHostname",     `
                                "Manufacturer",         `
                                "Model",                `
                                "ProcessorName",        `
                                "NrOfProcessors",       `
                                "RAM" ,                 `
                                "DiskDrive",            `
                                "OS",                   `
                                "LocalAdministrators",  `
                                "IPAddress",            `
                                #"SuffixOrigin",         `
                                "PSVersion"             `
                                | Export-Csv -Path $resultsFile -Delimiter ";" -Append 

        Remove-Variable results
        $sessions | Remove-PSSession
    }

    else {
        Write-Warning -Message "Computers listed below wasn't scanned before (they're not present in file `"$resultsFile`") and now script couldn't establish connection with them. They are offline or those are AD computer accounts of computers that was removed from use without disconnecting them from Active Directory domain." 
        $computersToScan | Sort-Object
        # to trzeba zmienić bo działa tylko wtedy gdy nie uda się nawiązać żadnej sesji w IFie, a to się raczej nei będzie zdarzało
    }
    
    Remove-Variable computersToScan
} 

else {
    write-host "All computers from $OUPath was already scanned."
}

#endregion



#region TRASH

#GetLocalAdministrators
#Get-LocalGroupMember -SID S-1-5-32-544 | select-object @{Name='LocalAdministrators';Expression={($_.Name).split('\')[-1]}} | Get-LocalUser -name {$_.LocalAdministrators} | select-object @{Name='LocalAdministrators';Expression={if ($TRUE -eq $_.Enabled ){$_.ToString() + "`(!`)"} else {$_.ToString() + "`(-`)"}}}


#GetLocalAccounts from PS < 5
#$adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
#$adsi.Children | where {$_.SchemaClassName -eq 'user'} | Foreach-Object {$groups = $_.Groups() | Foreach-Object {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)}$_}

#WYCIĄGNĄĆ ZE ZMIENNEJ $_ JAKIEŚ INFORMACJE I SPERSONALIZOWAĆ KOMUNIKAT BŁĘDU. PATRZ https://youtu.be/A6afjA5Q9eM?t=1240
#Write-Error -Message "Nie dziala dostep do AD, albo poswiadczenia sa bledne. Informacje systemowe: $Error[0]"


# Get-NetIPAddress | Where-Object {($_."InterfaceAlias" -like "Ethernet") -and ($_."AddressFamily" -like "*IPv4*" )} | Select-Object -ExpandProperty IPAddress
# Get-NetIPAddress -AddressState Preferred -AddressFamily IPv4 | select IPAddress,InterfaceAlias
#  $i = 1; (Get-NetConnectionProfile).InterfaceIndex | Get-NetIPAddress -InterfaceIndex {($_)} | Where-Object {$_.AddressFamily -like "IPv4"} | foreach-object {($i).ToString() + "." + (($_.IPAddress).ToString()); $i++}
# ((Get-NetConnectionProfile).InterfaceIndex | Get-NetIPAddress -InterfaceIndex {($_)} | Where-Object {$_.AddressFamily -like "IPv4"} | foreach-object {"(" + ($_.SuffixOrigin) + ": " + (($_.IPAddress).ToString()) + ": " + ((Get-NetAdapter -InterfaceIndex $_.InterfaceIndex).MacAddress) + ")"})

#Get-CimClass -Namespace root/CIMV2 | Where-Object CimClassName -like Win32* | Select-Object CimClassName -wyświetla wszystkie klasy CIM z których można pobierać dane

#$eeee | Select-Object -Property Producent, Model, PSComputerName, OS, ProcesorName, RAM, HDD
#$e.HDD.ForEach({[math]::Round($_ / 1GB,2)})
#$sessions | Remove-PSSession
#https://community.spiceworks.com/topic/932043-powershell-computer-age
#https://stackoverflow.com/questions/56980098/get-computer-manufacture-date-by-evaluate-cpu-dates-from-a-csv-file-using-powers



#Get-ADComputer -SearchBase "OU=5039,OU=Rejon,OU=Resort,DC=ad,DC=ms,DC=gov,DC=pl" -Filter * -property * | select-object -property Name, @{Name="LastLogon";Expression={[datetime]::FromFileTime($_.LastLogonTimeStamp)}} | Sort-Object -Property LastLogon

#endregion