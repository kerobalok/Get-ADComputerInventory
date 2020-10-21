#region Variables
$OUPath = "OU=5039,OU=Rejon,OU=Resort,DC=ad,DC=ms,DC=gov,DC=pl"
$computersFromOU = ("5039-marnow-k.ad.ms.gov.pl","slebd01.ad.ms.gov.pl")
$resultsFile = "scannedComputers.csv"
#endregion

#region Testing Credentials and if ther're correct getting computer DNSHostnames list from AD into $computersFromOU variable
#$credentials = Get-Credential

# Uncommend below to get computer list from AD. This is commented only for testing purposes.
# try {
#     $computersFromOU = (Get-ADComputer -Credential $credentials -SearchBase $OUPath -Filter * -Properties OperatingSystem, OperatingSystemServicePack, OperatingSystemVersion, WhenCreated -ErrorAction Stop | Where-Object {($_.OperatingSystem -like "*windows*") -and ($_.Enabled -eq $TRUE)}).DNSHostName
# }
# catch {
#     $somethingWentWrong = $_
#     #$blwrite-host "`t`n--- SOMETHING WENT WRONG ---`n"
#     if ($somethingWentWrong.Exception.Message -like "*Get-ADComputer*"){
#         Write-Warning -Message "W sytemie brakuje commandletu 'Get-ADComputer', a to prawdopodobnie znaczy brak modulu ActiveDirectory. Zainstalowane moduly mozesz sprawdzic poleceniem 'Get-Module'. Ponizej systemowy opis bledu"
#         Throw
#     }
#     else {
#         Throw
#     }
# }


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

            if (($PSVersionTable.PSVersion.Major) -ge 5) {
                $Win32_ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -property *
                $Win32_Processor = Get-CimInstance -ClassName Win32_Processor -property *
                $Win32_SystemEnclosure = Get-CimInstance -ClassName Win32_SystemEnclosure -property *
                $Win32_DiskDrive = Get-CimInstance -ClassName Win32_DiskDrive -property *

                new-object -TypeName PSCustomObject @{
                    ScanDate = (Get-Date -DisplayHint Date) #Get-Date -Format {dd.MM.yyyy}
                    PhysicalHostname = ([System.Net.Dns]::GetHostByName($env:computerName)).HOSTNAME
                    Manufacturer = $Win32_ComputerSystem.Manufacturer
                    Model = $Win32_ComputerSystem.Model
                    ComputerSerialNumber = $Win32_SystemEnclosure.SerialNumber
                    ProcessorName = $Win32_Processor.Name; #Get-Ciminstance -Query 'SELECT Name FROM Win32_Processor'
                    RAM = $Win32_ComputerSystem.TotalPhysicalMemory
                    DiskDrive = $Win32_DiskDrive.Size;
                    HDDPartitions = (Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3").Size;
                    #HDDPartitions = (Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3").Size | ForEach-Object {[math]::Round(($_ / 1GB),2)};
                    OS = (Get-CimInstance Win32_OperatingSystem -Property *).Name.Split("|") | Select-Object -First 1;
                    Annotation = ($PSVersionTable.PSVersion.Major)
                }
            }

            # Code for PowerShell with version less than 5
            else {
                $Win32_ComputerSystem = Get-WmiObject -Class Win32_ComputerSystem
                $Win32_Processor = Get-WmiObject -Class Win32_Processor
                $Win32_DiskDrive = Get-WmiObject -Class Win32_DiskDrive

                new-object -TypeName PSCustomObject @{
                    ScanDate = (Get-Date -DisplayHint Date);
                    PhysicalHostname = ([System.Net.Dns]::GetHostByName($env:computerName)).HOSTNAME #($env:computername + "." + $env:USERDNSDOMAIN);
                    Manufacturer = $Win32_ComputerSystem.Manufacturer;
                    Model = $Win32_ComputerSystem.Model;
                    ComputerSerialNumber = $NULL;
                    ProcessorName = $Win32_Processor.Name;
                    RAM = $Win32_ComputerSystem.TotalPhysicalMemory;
                    DiskDrive = $Win32_DiskDrive.Size;
                    HDDPartitions = $NULL;
                    OS = "ble1";
                    Annotation = ($PSVersionTable.PSVersion.Major);
                }
            }
        }
                
        # Adding alias LogicalHostname. It is required only for Windows Clusters which name in AD is differend from name of activer Hyper-V cluster member on which it runs.
        # For example, in AD cluster can have name "cluster.domain", but after connecting to it thru PowerShell and ask about ther name it will return name of physical server, not cluster.
        # This fact caused problems beacuse script saves to results to file - one from cluster name and one from physical server - member of cluster.
        
        # foreach ($computer in $results){

        #     if (($NULL -eq $computer.PSComputerName) -or ("" -eq $computer.PSComputerName)){
        #         $computer | Add-Member -MemberType AliasProperty -Name "LogicalHostname" -Value PhysicalHostname
        #         #write-host "ble $_.PhysicalHostname "
        #     }
        # }
        
        foreach ($computer in $results){
            if (!($computer.PSObject.Properties["PSComputerName"]) <#-or ($NULL -eq $computer.PSComputerName) -or ("" -eq $computer.PSComputerName)#>){
                $computer | Add-member -NotePropertyName "LogicalHostname" -NotePropertyValue "dupa"
            }
            else {
                $computer | Add-member -NotePropertyName "LogicalHostname" -NotePropertyValue "jas"
            }
        }



        # Saving results to a file
        $results | select-object -property `
                                "ScanDate", `
                                "PSComputerName", `
                                "LogicalHostname", `
                                "PhysicalHostname", `
                                "Manufacturer", `
                                "Model", `
                                "ProcessorName", `
                                "RAM" , `
                                "DiskDrive", `
                                "OS", `
                                "Annotation" `
                                | Export-Csv -Path $resultsFile -Delimiter ";" -Append 

        #Remove-Variable results
    }

    else {
        Write-Warning -Message "Cannot connect with computers (maybe they're offline):" 
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
#WYCIĄGNĄĆ ZE ZMIENNEJ $_ JAKIEŚ INFORMACJE I SPERSONALIZOWAĆ KOMUNIKAT BŁĘDU. PATRZ https://youtu.be/A6afjA5Q9eM?t=1240
#Write-Error -Message "Nie dziala dostep do AD, albo poswiadczenia sa bledne. Informacje systemowe: $Error[0]"


# Get-NetIPAddress | Where-Object {($_."InterfaceAlias" -like "Ethernet") -and ($_."AddressFamily" -like "*IPv4*" )} | Select-Object -ExpandProperty IPAddress

#Get-CimClass -Namespace root/CIMV2 | Where-Object CimClassName -like Win32* | Select-Object CimClassName -wyświetla wszystkie klasy CIM z których można pobierać dane

#$eeee | Select-Object -Property Producent, Model, PSComputerName, OS, ProcesorName, RAM, HDD
#$e.HDD.ForEach({[math]::Round($_ / 1GB,2)})
#$sessions | Remove-PSSession
#https://community.spiceworks.com/topic/932043-powershell-computer-age
#https://stackoverflow.com/questions/56980098/get-computer-manufacture-date-by-evaluate-cpu-dates-from-a-csv-file-using-powers
#endregion