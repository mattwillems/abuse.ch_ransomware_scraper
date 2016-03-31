#set the maximum amount of items to import from each website
$ItemMax = 200000
$Count = 0
$Path_32 = "C:\Program Files (x86)\LogRhythm\LogRhythm Job Manager\config\list_import\"
$Path_64 = "C:\Program Files\LogRhythm\LogRhythm Job Manager\config\list_import\"
$IPOutputFileName = "abuse.ch_ransom_IP.txt"
$URLOutputFileName = "abuse.ch_ransom_URL.txt"
$DomOutputFileName = "abuse.ch_ransom_Domain.txt"


if ((Test-Path -path $Path_32)){
	$IPFilePath = $Path_32 + $IPOutputFileName
	$URLFilePath = $Path_32 + $URLOutputFileName
	$DomFilePath = $Path_32 + $DomOutputFileName
}

if ((Test-Path -path $Path_64)){
	$IPFilePath = $Path_64 + $IPOutputFileName
	$URLFilePath = $Path_64 + $URLOutputFileName
	$DomFilePath = $Path_64 + $DomOutputFileName

}
else  {
    $path = Get-Location
    $IPFilePath = "$path\" + "$IPOutputFileName"
    $URLFilePath = "$path\" + "$URLOutputFileName"
    $DomFilePath = "$path\" + "$DomOutputFileName"
}

######################
#Ignoring SSL trust relationship within this PS script only
$netAssembly = [Reflection.Assembly]::GetAssembly([System.Net.Configuration.SettingsSection])
if($netAssembly) {
    $bindingFlags = [Reflection.BindingFlags] "Static,GetProperty,NonPublic"
    $settingsType = $netAssembly.GetType("System.Net.Configuration.SettingsSectionInternal")
    $instance = $settingsType.InvokeMember("Section", $bindingFlags, $null, $null, @())
        if($instance) {
            $bindingFlags = "NonPublic","Instance"
            $useUnsafeHeaderParsingField = $settingsType.GetField("useUnsafeHeaderParsing", $bindingFlags)
            if($useUnsafeHeaderParsingField) {
                $useUnsafeHeaderParsingField.SetValue($instance, $true)
            }
        }
}

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
######################

#delete import files if they exist already
if (Test-Path $IPFilePath) {
    Write-Host "Deleting existing IP file: $IPFilePath"
    Remove-Item $IPFilePath
    }
if (Test-Path $URLFilePath) {    
    Write-Host "Deleting existing URL file: $URLFilePath"
    Remove-Item $URLFilePath
    }
if (Test-Path $DomFilePath) {
    Write-Host "Deleting existing Domain file: $DomFilePath"
    Remove-Item $DomFilePath
    }

$IPURL = "https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt"
$URLURL = "https://ransomwaretracker.abuse.ch/downloads/RW_URLBL.txt"
$DomURL = "https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt"

$IPblocklist = New-Object Net.WebClient
$IPblocklist.DownloadString($IPURL) > tempIP.txt

#checks for blank text file and exits the program if the file is blank
Get-Content tempIP.txt | Measure-Object -word
if ($word -eq 0){
    Write-Host "Empty IP List"
    Break
    }
    
#Get-Content will put each individual line in the text file as an individual object which sets up the "if" loop below.
$IPblocklist = Get-Content tempIP.txt

# removes temp blocklist text file
Remove-Item tempIP.txt

$IPblocklist | ForEach-Object{
     #test if the IP starts with 1-3 digits and a dot
     if( $_ -match "^\d{1,3}\." -and $ItemMax -gt 0 ){
    
        #decrement count to limit the amount of objects in final text file
        $ItemMax = $ItemMax - 1
        
        #increase counter to count number of items on webpage
        $Count = $Count +1
        
    	#write to output
        $_ | out-file $IPFilePath -append

      }
}

####################################
#Now do all the same stuff for URLs#
####################################
$ItemMax = 200000
$Count = 0

$URLblocklist = New-Object Net.WebClient
$URLblocklist.DownloadString($URLURL) > tempURL.txt

#checks for blank text file and exits the program if the file is blank
Get-Content tempURL.txt | Measure-Object -word
if ($word -eq 0){
    Write-Host "Empty URL List"
    Break
    }
    
#Get-Content will put each individual line in the text file as an individual object which sets up the "if" loop below.
$URLblocklist = Get-Content tempURL.txt

# removes temp blocklist text file
Remove-Item tempURL.txt

$URLblocklist | ForEach-Object{
     #test if the string starts with http(s):. All entries in this list should.
     if( $_ -match "^https?:" -and $ItemMax -gt 0 ){
    
        #decrement count to limit the amount of objects in final text file
        $ItemMax = $ItemMax - 1
        
        #increase counter to count number of items on webpage
        $Count = $Count +1

        #write to output
        $_ | out-file $URLFilePath -append
    }
}

####################################
#Now do all the same stuff for Domains#
####################################
$ItemMax = 200000
$Count = 0

$Domblocklist = New-Object Net.WebClient
$Domblocklist.DownloadString($DomURL) > tempDom.txt

#checks for blank text file and exits the program if the file is blank
Get-Content tempDom.txt | Measure-Object -word
if ($word -eq 0){
        Write-Host "Empty Domain List"
    Break
    }
    
#Get-Content will put each individual line in the text file as an individual object which sets up the "if" loop below.
$Domblocklist = Get-Content tempDom.txt

# removes temp blocklist text file
Remove-Item tempDom.txt

$Domblocklist | ForEach-Object{
     #test if the domain starts with a word character. this should be enough to prevent bad data
     if( $_ -match "^\w" -and $ItemMax -gt 0 ){
    
        #decrement count to limit the amount of objects in final text file
        $ItemMax = $ItemMax - 1
        
        #increase counter to count number of items on webpage
        $Count = $Count +1

    	#write to output
        $_ | out-file $DomFilePath -append
        
      }
}