<#
.SYNOPSIS
This script automate the process of triaging, processing and scanning Windows images and memory dumps. It can run against many images as long that directory contains them.

--------------
## DESCRIPTION
The script accepts three parameters (-i, -e, -s).

--------------
## PARAMETER i
The image location. e.g E:\Path\to\image\

--------------
## PARAMETER e
The folder name that contains the artifacts. e.g. Artifacts

--------------
## PARAMETER s
This parameters is required to specify where you want the artifacts to be stored. e.g. E:\Path\

--------------
## EXAMPLE
.\heed.ps1 -i "K:\drive\images" -e "artifacts" -s "E:\saved\path\"

#>

param (
    [Parameter(Mandatory=$true)]
    [string]$i,

    [Parameter(Mandatory=$true)]
    [string]$e,

    [Parameter(Mandatory=$true)]
    [string]$s,

    # [Parameter(Mandatory=$false)]
    # [string]$sof,

    [Parameter()]
    [switch]$help
)
if($help) {
    Get-Help $MyInvocation.MyCommand.Definition
    exit
}


Write-Host @"      
===========+
Heed V.0.1 + 
===========+
                                
"@ -ForegroundColor Blue
Start-Sleep -Seconds 1
$startET = (Get-Date)
$scriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($currentUser)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        Write-Host "[+] The terminal is running with administrator privilege ($($currentUser.Name))" -ForegroundColor Green
    } else {
        Write-Host "[-] The terminal is running without an administrator privilege. The tool needs admin privilege for certain tasks to work flawlessly! $($currentUser.Name)" -ForegroundColor red
    }

function runCode {
    $imageLocation = $i
    $entityName = $e
    $storeLocation = $s
    write-host "[+] Image Location : $i" -ForegroundColor green
    write-host "[+] Folder Name : $e" -ForegroundColor green
    write-host "[+] Store Location : $s" -ForegroundColor green
    $colleLocation = New-Item -ItemType Directory -Path $storeLocation\$entityName   
    Write-host "[+] The result will be saved into $colleLocation" -ForegroundColor Cyan
    $kapeDir = checkKape
    $arsenalDir = checkArsenal
    $zircoliteDir = checkZircolite
    $lokiDir = checkLoki
    $volDir = checkVolatility
    write-host ""
    write-host "[+] Script location:        $scriptPath" -ForegroundColor Green
    write-host "[+] KAPE location:          $kapeDir" -ForegroundColor Green
    write-host "[+] Arsenal location:       $arsenalDir" -ForegroundColor Green
    write-host "[+] ZircoLite location:     $zircoliteDir" -ForegroundColor Green
    write-host "[+] LOKI location:          $lokiDir" -ForegroundColor Green
    write-host "[+] Volatility location:    $volDir" -ForegroundColor Green
    write-host ""
    validatingImges
    Write-Host "[+] The analyis on '$entityName' has finished and the result is saved into '$colleLocation'" -ForegroundColor green
    write-host ""
    Write-Host "[+] The result of the analysis on '$entityName' is shown below" -ForegroundColor Cyan
    Write-Host "[+] Collecting results from: $colleLocation" -ForegroundColor Cyan
    # GenerateReport -colleLocation $colleLocation
    $endET = (Get-Date)
    $totalTime = $endET - $startET
    write-host ""
    Write-Host "[+] Total Execution Time: $($totalTime.TotalMinutes ) minutes" -ForegroundColor Yellow
}
function checkKape {
    Set-Location $scriptPath
    write-host "[!] Checking if KAPE exitsts" -ForegroundColor Cyan
    $kapeDir = Get-ChildItem $scriptPath -Directory | Where-Object { $_.Name -like "KAPE*" } | ForEach-Object { if (Test-Path "$($_.FullName)\kape.exe") { $_.FullName}} | Select-Object -first 1 
    if (Test-Path "$kapeDir\kape.exe") {
        write-host "[+] kape.exe exists in $kapeDir" -ForegroundColor Yellow
        return $kapeDir
    }
    else {
        write-host "[-] KAPE is not exists" -ForegroundColor Red
        Write-Host "[-] The folder does not contain KAPE in the same directory as the PowerShell script: $scriptPath" -ForegroundColor Red
        $kapeLink = "https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape"
        write-host "[-] If you don't have KAPE Please download from: $kapeLink" -ForegroundColor Red        
    }
} 
function checkArsenal {
    write-host "[+] Checking if Arsenal Image Mounter exitsts" -ForegroundColor Cyan
    $arsenalDir = Get-ChildItem $scriptPath -Directory | Where-Object { $_.Name -like "Arsenal*" } | ForEach-Object { if (Test-Path "$($_.FullName)\aim_cli.exe") { $_.FullName}} | Select-Object -first 1 

    if (Test-Path "$arsenalDir\aim_cli.exe") {
        write-host "[+] aim_cli.exe exists in: $arsenalDir" -ForegroundColor Yellow
        return $arsenalDir
    }
    else {
        write-host "[-] Arsenal Image Mounter is not exists" -ForegroundColor Red
        Write-Host "[-] The folder does not contain Arsenal Image Mounter in the same directory as the PowerShell script: $scriptPath" -ForegroundColor Red
        $arsenalLink = "https://arsenalrecon.com/downloads"
        write-host "[-] If you don't have Arsenal Image Mounter Please download from: $arsenalLink" -ForegroundColor Red 
    }
}
function checkZircolite {
    write-host "[!] Checking if Zircolite exitsts" -ForegroundColor Cyan
    $zircoliteDir = Get-ChildItem $scriptPath -Directory | Where-Object { $_.Name -like "Zircolite*" } | ForEach-Object { if (Test-Path "$($_.FullName)\zircolite_win10.exe") { $_.FullName}} | Select-Object -first 1 
    if (Test-Path "$zircoliteDir\zircolite_win10.exe") {
        write-host "[+] zircolite_win10.exe exists in: $zircoliteDir" -ForegroundColor Yellow
        return $zircoliteDir
    }
    else {
        write-host "[-] Zircolite is not exists" -ForegroundColor Red
        Write-Host "[-] The folder does not contain Zircolite in the same directory as the PowerShell script: $scriptPath" -ForegroundColor Red
        $ZircoliteLink = "https://github.com/wagga40/Zircolite/releases"
        write-host "[-] If you don't have Zircolite Please download from: $ZircoliteLink" -ForegroundColor Red 
    }
}
function checkLoki {
    write-host "[!] Checking if LOKI exitsts" -ForegroundColor Cyan
    $lokiDir = Get-ChildItem $scriptPath -Directory | Where-Object { $_.Name -like "LOKI*" } | ForEach-Object { if (Test-Path "$($_.FullName)\loki.exe") { $_.FullName}} | Select-Object -first 1 
    if (Test-Path "$lokiDir\loki.exe") {
        write-host "[+] loki.exe exists in: $lokiDir" -ForegroundColor Yellow
        return $lokiDir
    }
    else {
        write-host "[-] LOKI is not exists" -ForegroundColor Red
        Write-Host "[-] The folder does not contain LOKI in the same directory as the PowerShell script: $scriptPath" -ForegroundColor Red
        $lokiLink = "https://github.com/Neo23x0/Loki/releases"
        write-host "[-] If you don't have Zircolite Please download from: $lokiLink" -ForegroundColor Red 
    }
}
function checkVolatility {
    write-host "[+] Checking if Volatility exitsts" -ForegroundColor Cyan
    $volDir = Get-ChildItem $scriptPath -Directory | Where-Object { $_.Name -like "Volatility*" } | ForEach-Object { if (Test-Path "$($_.FullName)\vol.py") { $_.FullName}} | Select-Object -first 1 

    if (Test-Path "$volDir\vol.py") {
        write-host "[+] vol.py exists in: $volDir" -ForegroundColor Yellow
        return $volDir
    }
    else {
        write-host "[-] Volatility 3 is not exists" -ForegroundColor Red
        Write-Host "[-] The folder does not contain Volatility Script in the same directory as the PowerShell script: $scriptPath" -ForegroundColor Red
        $volLink = "https://github.com/volatilityfoundation"
        write-host "[-] If you don't have Volatility! Please download from: $volLink" -ForegroundColor Red 
    }
}
function runArsenal($filePath,$argumentList) {
    try {
        Set-location "$arsenalDir"
        write-host "[+] Arsenal directory: $arsenalDir" -ForegroundColor yellow
        write-host "[+] Running Arsenal" -ForegroundColor yellow
        start-process -FilePath $arsenalDir\aim_cli.exe -ArgumentList "/dismount /force" -WindowStyle Hidden
        Start-Sleep -Seconds 5
        write-host "[+] Used the following argument for Arsenal: $argumentList" -ForegroundColor Yellow
        start-process -FilePath $arsenalDir\aim_cli.exe -ArgumentList $argumentList -WindowStyle Hidden
        Start-Sleep -Seconds 5
        Set-location $scriptPath
    }
    catch {
        Write-Host "[-] Something went wrong happened when running Arsenal Image Mounter function" -ForegroundColor blue
        Write-Host "Error: $_. Exception: $($_.Exception)" -ForegroundColor Red
    }
}
function runKapeCollection {
    try {
        Set-location $kapeDir
        write-host "[+] KAPE collection started" -ForegroundColor yellow
        write-host "[+] KAPE collection from $file" -ForegroundColor yellow 
        Start-Sleep -Seconds 2
        .\kape.exe --tsource $driveLetter --tdest "$colleLocation\$file\KAPE\collection" --target  BrowserCache,Antivirus,CombinedLogs,EvidenceOfExecution,Exchange,RegistryHives,RemoteAdmin,WebBrowsers,WebServers,BITS,CertUtil,GroupPolicy,LogFiles,ScheduledTasks,SRUM,StartupFolders,WBEM,WindowsFirewall,'$J','$MFT' --vhdx "$file" --zv false
        write-host "[+] KAPE Collection is done" -ForegroundColor green     
        Set-location $scriptPath
    }
    catch {
        Write-Host "[-] Something wrong happened when running KAPE collection function" -ForegroundColor blue
        Write-Host "Error: $_. Exception: $($_.Exception)" -ForegroundColor red
    }
}
function runKapeProcessing {
    try {
        Set-location $colleLocation\$file\KAPE\collection\
        $imagePathVHDX = Get-ChildItem *.vhdx| Sort-Object LastWriteTime | Select-Object -Last 1 | ForEach-Object {$_.FullName}
        Write-host "[+] Triaged VHDX $imagePathVHDX" -ForegroundColor yellow 
        $triagLetter = (Mount-DiskImage -ImagePath $imagePathVHDX -StorageType VHDX -PassThru | Get-Disk | Get-Partition | Get-Volume).DriveLetter
        Set-location $kapeDir
        Write-host "[+] Disk is mounted to $triagLetter" -ForegroundColor yellow 
        Write-host "[+] KAPE directory is $kapeDir" -ForegroundColor yellow 
        .\kape.exe --msource $triagLetter":" --mdest $colleLocation\$file\KAPE\processing --module !EZParser,LogParser,MFTECmd,AmcacheParser,AppCompatCacheParser --mef csv
        Start-Sleep -Seconds 2
        write-host "[+] Dismounting triaged image" -ForegroundColor yellow   
        Dismount-DiskImage -ImagePath $imagePathVHDX
        write-host "[+] KAPE Processing is done" -ForegroundColor green   
        Set-location $scriptPath
    }
    catch {
        Write-Host "[-] Something wrong happened when running KAPE processing function" -ForegroundColor blue
        Write-Host "Error: $_. Exception: $($_.Exception)" -ForegroundColor Red
    }
}
function runZircoLite {
    try {
        Set-location $colleLocation\$file\KAPE\collection\
        $imagePathVHDX = Get-ChildItem *.vhdx| Sort-Object LastWriteTime | Select-Object -Last 1 | ForEach-Object {$_.FullName}
        Write-host "[+] Triaged VHDX $imagePathVHDX" -ForegroundColor yellow 
        $triagLetter = (Mount-DiskImage -ImagePath $imagePathVHDX -StorageType VHDX -PassThru | Get-Disk | Get-Partition | Get-Volume).DriveLetter
        Set-location $zircoliteDir
        #get the triage letter if not matched with mounted drive G:\*\
        $folderNameLetter = Get-ChildItem -Path $triagLetter":\*" -Directory -Filter "?" | Select-Object -ExpandProperty Name
        Write-host "[+] ZircoLite directory is $zircoliteDir" -ForegroundColor yellow
        $eventLocation = "$triagLetter`:\$folderNameLetter\Windows\System32\winevt\logs\"
        if (Test-Path $eventLocation) {
            Write-host "[+] Event Location at $eventLocation" -ForegroundColor yellow
            Start-Sleep -Seconds 1
            Write-host "[+] ZircoLite is launching" -ForegroundColor yellow
            .\zircolite_win10.exe --evtx $eventLocation --ruleset $zircoliteDir\rules\rules_windows_generic_full.json -o $colleLocation\$file\zircolite\result-$entityName-$file.json
            Start-Sleep -Seconds 2
            Write-host "[+] ZircoLite is done its analysis and written to $colleLocation\$file\zircolite\" -ForegroundColor green
            Write-host "[+] ZircoLite is done" -ForegroundColor green
        } 
        else {
            write-host "[-] Triage image does not contain the EventLogs at $eventLocation" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "[-] An error occurred while running ZircoLite: $_" -ForegroundColor Red
    }
}
function runLoki {
    try {
        Set-location "$arsenalDir"
        write-host "[+] Starting LOKI function" -ForegroundColor yellow
        write-host "[+] Arsenal directory: $arsenalDir" -ForegroundColor yellow
        write-host "[+] Running Arsenal to mount the image to be scanned with LOKI" -ForegroundColor yellow
        Start-Sleep -Seconds 1
        write-host "[+] Creating folder to collect LOKI's result: $colleLocation\$file\loki" -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        $GetLetter = (Get-Disk -FriendlyName "Arsenal*" | Get-Partition | Get-Volume).DriveLetter
        Start-Sleep -Seconds 4
        $AllLetters = $GetLetter
        Start-Sleep -Seconds 4
        Write-Host "[+] Checking [$AllLetters] Drives" -ForegroundColor Yellow
        $AllLettersNoSpace = $AllLetters -replace '[^A-Za-z]'
        Write-Host "[+] Number of Mounted Volumes is:" $AllLettersNoSpace.length -ForegroundColor Yellow
        #Checking the volumes, if mounted sucessfuly, it will Scan the volume with Loki
        For($i=0;$i -lt $AllLettersNoSpace.length;$i++){
            $driveLetter = $AllLettersNoSpace[$i]
            Write-Host "[+] Checking the Drive $driveLetter" -ForegroundColor Yellow
            if ((Get-volume -DriveLetter "$driveLetter").size / 10GB -gt 1) {
                Write-Host "[+] The image is legit and accessible" -ForegroundColor yellow
                Set-location "$lokiDir"
                Start-Sleep -Seconds 3
                write-host "[+] LOKI will Start now" -ForegroundColor green     
                .\loki.exe -p $driveLetter`:\ -l "$colleLocation\$file\loki\$driveLetter`_$file`_result.csv" --noprocscan --nopesieve --csv
                Set-location $scriptPath
            }
            else {
                write-host "[-] Mounted image isn't accessible" -ForegroundColor Red
            }
        }
    } catch {
        Write-Host "[-] An error occurred while running LOKI: $_" -ForegroundColor Red

    }
}


function runVolatility {
    # Check for Python 3
    $python3Path = where.exe python3 2>$null | Select-Object -First 1
    if ($null -eq $python3Path) {
        Write-Error "Python 3 is not found. Please install Python 3 and ensure it is added to PATH environment variable."
        exit 1
    } else {
        $version = & "$python3Path" --version 2>&1
        if (-not $version.StartsWith("Python 3")) {
            Write-Error "Python 3 is required. Current version is $version"
            exit 1
        }
    }
    # Commands to run using volatility
    $Commands = "windows.pslist", "windows.pstree", "windows.dlllist", "windows.cmdline", "windows.malfind", "windows.netstat", "windows.psscan", "windows.netscan"
    $mem = Split-Path -Path $img -Parent 
    $MemoryDumps = Get-ChildItem -Path $mem -Filter "*.dmp" -Recurse | Select-Object -ExpandProperty FullName
    set-location $volDir
    foreach ($MemoryDump in $MemoryDumps) {
        write-host "[+] MemoryDump: $MemoryDump" -ForegroundColor Yellow
        foreach ($command in $Commands) {
            # Full command to execute
            $arguments = "`"$VolatilityPath`" -f `"$MemoryDump`" $command"
            write-host "Volatility arguments: $arguments" -ForegroundColor Cyan
            & "$python3Path" vol.py -f $MemoryDump -r json $command | Out-File -FilePath "$colleLocation\$file\Volatility\$command.json"
        }
    }
}


function runScript {
    $GetLetter = (Get-Disk -FriendlyName "Arsenal*" | Get-Partition | Get-Volume).DriveLetter
    $AllLetters = $GetLetter
    Write-Host "[+] Checking $AllLetters" -ForegroundColor Yellow
    $AllLettersNoSpace = $AllLetters -replace '[^A-Za-z]'
    Write-Host "[+] Number of Mounted Volumes is:" $AllLettersNoSpace.Length -ForegroundColor Yellow
    Write-Host "[+] The Volume Letter is: $AllLettersNoSpace" -ForegroundColor Yellow
    # Checking the volumes, if mounted successfully, it will go through Arsenal, KAPE, Zircolite
    foreach ($driveLetter in $AllLettersNoSpace) {
        Write-Host "[!] Checking the Drive $driveLetter" -ForegroundColor Cyan
        if (Test-Path "$driveLetter`:\") {
            Write-Host "[+] The image is mounted and accessible" -ForegroundColor Yellow
            # Check for required folders
            $requiredFolders = @("Windows", "Users")
            $missingFolders = $requiredFolders | Where-Object { -not (Test-Path "$driveLetter`:\$_") }
            if ($missingFolders.Count -eq 0 -and ((Get-Volume -DriveLetter $driveLetter).Size / 10GB -gt 1)) {
                Write-Host "[+] Folders 'Windows' and 'Users' exist in drive $driveLetter" -ForegroundColor Yellow
                Write-Host "[+] Image mounted to the Drive Letter $driveLetter" -ForegroundColor Yellow
                Write-Host "[+] Starting KAPE Process" -ForegroundColor Yellow
                Write-Host "[+] Running KAPE Collection" -ForegroundColor Yellow
                runKapeCollection # Running Kape Collection
                Write-Host "[+] Running KAPE Processing" -ForegroundColor Yellow
                runKapeProcessing # Running Kape Processing
                Write-Host "[+] Running ZircoLite" -ForegroundColor Yellow
                runZircoLite # Running ZirocLite
                Write-Host ""
                Set-Location $scriptPath
                Write-Host "[+] Done from ZircoLite" -ForegroundColor Cyan
                Write-Host "[+] Running Loki" -ForegroundColor Cyan
                runLoki #run LOKI 
                Write-Host "[+] Evidence collected to $colleLocation\$file\" -ForegroundColor Cyan
                Write-Host "[+] Loki has finished" -ForegroundColor green
                Write-Host "[+] Running Volatility" -ForegroundColor Cyan
                runVolatility #run Volatility
                Write-Host "[+] Volatility has finished" -ForegroundColor green
                Write-Host "[+] Analysis Completed" -ForegroundColor green
                
            }
            else {
                Write-Host "[!] Required folders are missing. Skipping drive $driveLetter" -ForegroundColor DarkMagenta
                Write-Host "[!] Missing folders: $missingFolders" -ForegroundColor DarkMagenta
            }
        }
        else {
            Write-Host "[!] The mounted image is not accessible" -ForegroundColor Red
            Write-Host "[!] Something wrong with Arsenal Image Mounter" -ForegroundColor Red
            Write-Host "[-] Exiting the code" -ForegroundColor Red
        }
    }
}

function validatingImges {
    Start-Sleep -Seconds 3
    Write-Host "[+] Starting to validate the Images" -ForegroundColor Green
    $files = Get-ChildItem -Path $imageLocation -Recurse | Where-Object { $_.Length -gt 1GB } 
    $extensions = $files.Extension | Select-Object -Unique
    $sample = $files | Get-Random -count 5
    if ($extensions -contains ".001" -and $extensions -contains ".002" -and $extensions -contains ".003" -and $extensions -contains ".004" -and $extensions -contains ".005") {
        write-host "[+] Sample of images found within the directory: $sample" -ForegroundColor blue
        write-host ''
            $file = Get-ChildItem -Path $imageLocation -Filter "*.001" -Name
            write-host "[+] This is a Multi Part Raw image" -ForegroundColor Yellow
            $img = "$imageLocation`\$file"
            write-host "[+] Chosen Image to be mounted: $img" -ForegroundColor yello
            $argumentList = "/mount /filename=`"$img`" /fakesig /provider=MultiPartRaw /writeoverlay=`"$img.diff`" /autodelete"
            write-host "[+] Running the script against: $file" -ForegroundColor yellow
            New-Item -ItemType Directory -Path $colleLocation\$file\Zircolite > $null
            New-Item -ItemType Directory -Path $colleLocation\$file\Loki > $null
            New-Item -ItemType Directory -Path $colleLocation\$file\KAPE > $null
            New-Item -ItemType Directory -Path $colleLocation\$file\Volatility > $null
            Start-Sleep -Seconds 1
            runArsenal($argumentList) -filePath $file.FullName
            runScript
            }
    elseif ($extensions -contains ".vmdk") {
        write-host "[+] Sample of images found within the directory: $sample" -ForegroundColor blue
        write-host ''
        $file = Get-ChildItem -Path $imageLocation -Exclude "*000*.vmdk" -Filter '*.vmdk' -Name
        write-host "[+] This is a VMDK image" -ForegroundColor Yellow
        $img = "$imageLocation`\$file"
        write-host "[+] Chosen Image to be mounted: $img" -ForegroundColor yello
        $argumentList = "/mount /filename=`"$img`" /fakesig /writeoverlay=`"$img.diff`" /autodelete"
        write-host "[+] Running the script against: $file" -ForegroundColor yellow
        New-Item -ItemType Directory -Path $colleLocation\$file\Zircolite > $null
        New-Item -ItemType Directory -Path $colleLocation\$file\Loki > $null
        New-Item -ItemType Directory -Path $colleLocation\$file\KAPE > $null
        New-Item -ItemType Directory -Path $colleLocation\$file\Volatility > $null
        Start-Sleep -Seconds 1
        runArsenal($argumentList) -filePath $file.FullName
        runScript
    }
    elseif ($extensions -contains ".001") {
        write-host "[+] Sample of images found within the directory: $sample" -ForegroundColor blue
        write-host ''
        $files = Get-ChildItem -Path $imageLocation -Filter '*.001' -Recurse
        foreach ($file in $files) {
            write-host "[+] Validating the image" -ForegroundColor Yellow
            write-host "[+] This is a dd image type" -ForegroundColor Yellow
            $img = $file.FullName
            write-host "[+] Chosen Image to be mounted: $img" -ForegroundColor yellow
            $argumentList = "/mount /filename=`"$img`" /fakesig /fakembr /writeoverlay=`"$img.diff`" /autodelete"
            write-host "[+] Running the script against: $file" -ForegroundColor yellow
            New-Item -ItemType Directory -Path $colleLocation\$file\Zircolite > $null
            New-Item -ItemType Directory -Path $colleLocation\$file\Loki > $null
            New-Item -ItemType Directory -Path $colleLocation\$file\KAPE > $null
            New-Item -ItemType Directory -Path $colleLocation\$file\Volatility > $null
            Start-Sleep -Seconds 1
            runArsenal($argumentList) -filePath $file.FullName
            runScript
        }
    }
    elseif ($extensions -contains ".E01") {
        write-host "[+] Sample of images found within the directory: $sample" -ForegroundColor blue
        write-host ''
        $files = Get-ChildItem -Path $imageLocation -Filter '*.E01' -Recurse
        foreach ($file in $files) {
            write-host "[+] Validating the image" -ForegroundColor Yellow
            write-host "[+] This is a dd image type" -ForegroundColor Yellow
            $img = $file.FullName
            write-host "[+] Chosen Image to be mounted: $img" -ForegroundColor yellow
            $argumentList = "/mount /filename=`"$img`" /fakesig /fakembr /writeoverlay=`"$img.diff`" /autodelete /provider=LibEwf"
            write-host "[+] Running the script against: $file" -ForegroundColor yellow
            New-Item -ItemType Directory -Path $colleLocation\$file\Zircolite > $null
            New-Item -ItemType Directory -Path $colleLocation\$file\Loki > $null
            New-Item -ItemType Directory -Path $colleLocation\$file\KAPE > $null
            New-Item -ItemType Directory -Path $colleLocation\$file\Volatility > $null
            Start-Sleep -Seconds 1
            runArsenal($argumentList) -filePath $file.FullName
            runScript
        }
    }        
    elseif (($extensions -notcontains ".001" -and $extensions -notcontains ".002" -and $extensions -notcontains ".003" -and $extensions -notcontains ".004" -and $extensions -notcontains ".005") -and ($extensions -notcontains ".vmdk")) {
        foreach ($file in $files) {
            write-host "[+] Found the following images $files" -ForegroundColor Yellow
            write-host "[+] Running the script against: $file" -ForegroundColor yellow
            $img = "$imageLocation`\$file"
            $argumentList = "/mount /filename=`"$img`" /fakesig /writeoverlay=`"$img.diff`" /autodelete"
            New-Item -ItemType Directory -Path $colleLocation\$file\Zircolite > $null
            New-Item -ItemType Directory -Path $colleLocation\$file\Loki > $null
            New-Item -ItemType Directory -Path $colleLocation\$file\KAPE > $null
            New-Item -ItemType Directory -Path $colleLocation\$file\Volatility > $null
            Start-Sleep -Seconds 1
            runArsenal($argumentList) -filePath $file.FullName 
            runScript
        }
    } 
    else {
        Write-Host "[-] Check the folder as there no images that have more than 10GB in size" -ForegroundColor red
    }
}


runCode

