#region Variables
$OUPath = "OU=komputery, OU=5039,OU=Rejon,OU=Resort,DC=ad,DC=ms,DC=gov,DC=pl"
#$computersFromOU = ("slebd01.ad.ms.gov.pl", "slesa01.ad.ms.gov.pl", "5039-sleDNS00.ad.ms.gov.pl")
$resultsFile = "scannedComputers.csv"
#endregion

#region Testing Credentials and if ther're correct getting computer DNSHostnames list from AD into $computersFromOU variable
#$credentials = Get-Credential
try {
    $computersFromOU = (Get-ADComputer -Credential $credentials -SearchBase $OUPath -Filter * -Properties OperatingSystem, OperatingSystemServicePack, OperatingSystemVersion, WhenCreated -ErrorAction Stop | Where-Object {($_.OperatingSystem -like "*windows*") -and ($_.Enabled -eq $TRUE)}).DNSHostName
}
catch {
    $somethingWentWrong = $_
    #$blwrite-host "`t`n--- SOMETHING WENT WRONG ---`n"
    if ($somethingWentWrong.Exception.Message -like "*Get-ADComputer*"){
        Write-Warning -Message "W sytemie brakuje commandletu 'Get-ADComputer', a to prawdopodobnie znaczy brak modulu ActiveDirectory. Zainstalowane moduly mozesz sprawdzic poleceniem 'Get-Module'. Ponizej systemowy opis bledu"
        Throw
    }
    else {
        Throw
    }
    #write-error $_
    
    #WYCIĄGNĄĆ ZE ZMIENNEJ $_ JAKIEŚ INFORMACJE I SPERSONALIZOWAĆ KOMUNIKAT BŁĘDU. PATRZ https://youtu.be/A6afjA5Q9eM?t=1240
    #Write-Error -Message "Nie dziala dostep do AD, albo poswiadczenia sa bledne. Informacje systemowe: $Error[0]"
}
#endregion 


#region Checking if file with reults from previous scans exist and if so, skipping computers included in that file (they were already scanned).
$computersToScan = @()
if ($TRUE -eq (Test-Path -LiteralPath $resultsFile)){
    $alreadyScannedComputers = Import-Csv -Path $resultsFile -delimiter ";"  | Select-Object -ExpandProperty "PSComputerName"

    ForEach ($computerFromOU in $computersFromOU){
        if ($alreadyScannedComputers -notcontains $computerFromOU){
            $computersToScan += $computerFromOU
        }
    }
}
#endregion


#region Scanning section
# if variable $computersToScan exists, it means that there are not scan results in file $resultsFile and that means, that those computers wasn't scanned before
if ($TRUE -eq $computersToScan) { 
    $sessions = New-PSSession -ComputerName $computersToScan <#-ErrorAction SilentlyContinue#> -Credential $credentials

    $results = Invoke-Command -Session $sessions -ScriptBlock {
        $Win32_ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -property *
        $Win32_Processor = Get-CimInstance -ClassName Win32_Processor -property *
        $Win32_SystemEnclosure = Get-CimInstance -ClassName Win32_SystemEnclosure -property *
        $Win32_DiskDrive = Get-CimInstance -ClassName Win32_DiskDrive -property *

        [pscustomobject]@{
            ScanDate = (Get-Date -DisplayHint Date) #Get-Date -Format {dd.MM.yyyy}
            Manufacturer = $Win32_ComputerSystem.Manufacturer
            Model = $Win32_ComputerSystem.Model
            ComputerSerialNumber = $Win32_SystemEnclosure.SerialNumber
            ProcessorName = $Win32_Processor.Name;
            ProcessorCores = $Win32_Processor.NumberOfCores;
            ProcessorNrLogicalProcessors = $Win32_Processor.NumberOfLogicalProcessors; # $env:NUMBER_OF_PROCESSORS
            ProcessorThreatCount = $Win32_Processor.ThreadCount;
            RAM = $Win32_ComputerSystem.TotalPhysicalMemory
            DiskDrive = $Win32_DiskDrive.Size;

            HDDPartitions = (Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3").Size;
            OS = (Get-CimInstance Win32_OperatingSystem -Property *).Name.Split("|") | Select-Object -First 1;
        }
    }

    # saving scan results to a file with setting property order. 
    # IMPORTANT THING ! - property PSComputerName is part of object $results and it is generated automatically due running Invoke-Command. It is not property returned from remote computers, like other properties. 
    $results | select-object -property "ScanDate", "PSComputerName" | Export-Csv -Path $resultsFile -Delimiter ";" -Append 

    #clearing variables
    Remove-Variable computersToScan
    Remove-Variable results
} else {"Wszystkie komputery z OU byly juz wczesniej przeskanowane "}

#endregion

#region TRASH
#Get-CimClass -Namespace root/CIMV2 | Where-Object CimClassName -like Win32* | Select-Object CimClassName -wyświetla wszystkie klasy CIM z których można pobierać dane

#$eeee | Select-Object -Property Producent, Model, PSComputerName, OS, ProcesorName, RAM, HDD
#$e.HDD.ForEach({[math]::Round($_ / 1GB,2)})
#$sessions | Remove-PSSession
#https://community.spiceworks.com/topic/932043-powershell-computer-age
#https://stackoverflow.com/questions/56980098/get-computer-manufacture-date-by-evaluate-cpu-dates-from-a-csv-file-using-powers
#endregion