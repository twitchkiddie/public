#Message to send to users
$MessageTemplateID = ''

#application ID
$AppId = ''

#Application Secret (should be in a vault)
$AppSecret = ''

#Tenant Name
$TenantName = ''

#Get version numbers
function Invoke-GetVersionNumbers{
    $Windows10HTML = Invoke-RestMethod 'https://docs.microsoft.com/en-us/windows/release-health/release-information'
    $Windows10 = $Windows10HTML | Select-String '(?smi)<td>([^<]*)<\/td>' -AllMatches

    $Windows11HTML = Invoke-RestMethod 'https://docs.microsoft.com/en-us/windows/release-health/windows11-release-information'
    $Windows11 = $Windows11HTML | Select-String '(?smi)<td>([^<]*)<\/td>' -AllMatches
    $Versions = @(
        [pscustomobject]@{OS='Windows 11';MajorVersion=$Windows11.Matches[0].Groups[1].Value.SubString(0,4);Build=$Windows11.Matches[3].Groups[1].Value;ReleaseDate=$Windows11.Matches[2].Groups[1].Value}
        [pscustomobject]@{OS='Windows 11';MajorVersion=$Windows11.Matches[6].Groups[1].Value;Build=$Windows11.Matches[9].Groups[1].Value;ReleaseDate=$Windows11.Matches[2].Groups[1].Value}
        [pscustomobject]@{OS='Windows 10';MajorVersion=$Windows10.Matches[0].Groups[1].Value;Build=$Windows10.Matches[3].Groups[1].Value;ReleaseDate=$Windows10.Matches[2].Groups[1].Value}
        [pscustomobject]@{OS='Windows 10';MajorVersion=$Windows10.Matches[6].Groups[1].Value;Build=$Windows10.Matches[9].Groups[1].Value;ReleaseDate=$Windows10.Matches[2].Groups[1].Value}
        [pscustomobject]@{OS='Windows 10';MajorVersion=$Windows10.Matches[12].Groups[1].Value;Build=$Windows10.Matches[15].Groups[1].Value;ReleaseDate=$Windows10.Matches[2].Groups[1].Value}
 
    )
    return $Versions
}

#Get a token
function Get-AuthTokenSP {
    $AppId = $AppId
    $AppSecret = $AppSecret
    $Scope = "https://graph.microsoft.com/.default"
    $TenantName = $TenantName

    $Url = "https://login.microsoftonline.com/$TenantName/oauth2/v2.0/token"

    # Add System.Web for urlencode
    Add-Type -AssemblyName System.Web

    # Create body
    $Body = @{
        client_id = $AppId
	    client_secret = $AppSecret
	    scope = "offline_access $($Scope)"
	    grant_type = 'client_credentials'
    }

    # Splat the parameters for Invoke-Restmethod for cleaner code
    $PostSplat = @{
        ContentType = 'application/x-www-form-urlencoded'
        Method = 'POST'
        # Create string by joining bodylist with '&'
        Body = $Body
        Uri = $Url
    }

    # Request the token!
    $Request = Invoke-RestMethod @PostSplat

    if($Request.access_token){

    # Creating header for Authorization token

    $authHeader = @{
        'Content-Type'='application/json'
        'Authorization'="Bearer "+$Request.access_token
        'ExpiresOn'= $Request.expires_in
        }

    return $authHeader
    #Return $Request.access_token
    }

    else {

        Write-Host
        Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
        Write-Host
        break

    }
}

#Create the json required for the policy
function Invoke-CreateComplianceJSON($description,$displayName,$VersionNumber){
$JSON = @"
{
    "@odata.type": "#microsoft.graph.windows10CompliancePolicy",
    "roleScopeTagIds": [
        "0"
    ],
    "description": "$($description)",
    "displayName": "$($displayName)",
    "version": 1,
    "passwordRequired": false,
    "passwordBlockSimple": false,
    "passwordRequiredToUnlockFromIdle": false,
    "passwordMinutesOfInactivityBeforeLock": null,
    "passwordExpirationDays": null,
    "passwordMinimumLength": null,
    "passwordMinimumCharacterSetCount": null,
    "passwordRequiredType": "deviceDefault",
    "passwordPreviousPasswordBlockCount": null,
    "requireHealthyDeviceReport": false,
    "osMinimumVersion": "$($VersionNumber)",
    "osMaximumVersion": null,
    "mobileOsMinimumVersion": null,
    "mobileOsMaximumVersion": null,
    "earlyLaunchAntiMalwareDriverEnabled": false,
    "bitLockerEnabled": false,
    "secureBootEnabled": false,
    "codeIntegrityEnabled": false,
    "storageRequireEncryption": false,
    "activeFirewallRequired": false,
    "defenderEnabled": false,
    "defenderVersion": null,
    "signatureOutOfDate": false,
    "rtpEnabled": false,
    "antivirusRequired": false,
    "antiSpywareRequired": false,
    "deviceThreatProtectionEnabled": false,
    "deviceThreatProtectionRequiredSecurityLevel": "unavailable",
    "configurationManagerComplianceRequired": false,
    "tpmRequired": false,
    "deviceCompliancePolicyScript": null,
    "validOperatingSystemBuildRanges": [],
    "scheduledActionsForRule": [
        {
            "id": "e2ac16f1-a55b-43df-99ee-88548bb8bb5f",
            "ruleName": null,
            "scheduledActionConfigurations": [
                {
                    "id": "bfa63053-8e09-462a-8e22-0c5caceabe48",
                    "gracePeriodHours": 720,
                    "actionType": "block",
                    "notificationTemplateId": "00000000-0000-0000-0000-000000000000",
                    "notificationMessageCCList": []
                },
                {
                    "id": "efc08519-2fde-44c0-bd59-b05569bb7c82",
                    "gracePeriodHours": 24,
                    "actionType": "notification",
                    "notificationTemplateId": "$($MessageTemplateID)",
                    "notificationMessageCCList": []
                },
                {
                    "id": "d660a121-6515-4bc0-9a1b-e546a16dad0f",
                    "gracePeriodHours": 48,
                    "actionType": "notification",
                    "notificationTemplateId": "$($MessageTemplateID)",
                    "notificationMessageCCList": []
                },
                {
                    "id": "d95af6cf-b455-49d4-8d6e-e87fc6d97811",
                    "gracePeriodHours": 72,
                    "actionType": "notification",
                    "notificationTemplateId": "$($MessageTemplateID)",
                    "notificationMessageCCList": []
                },
                {
                    "id": "0dcc79da-c14c-4fee-b3ed-c07bcae1821f",
                    "gracePeriodHours": 96,
                    "actionType": "notification",
                    "notificationTemplateId": "$($MessageTemplateID)",
                    "notificationMessageCCList": []
                },
                {
                    "id": "fa1d3a8f-9f04-4955-a6e4-d3af61563b0a",
                    "gracePeriodHours": 120,
                    "actionType": "notification",
                    "notificationTemplateId": "$($MessageTemplateID)",
                    "notificationMessageCCList": []
                },
                {
                    "id": "fa1d3a8f-9f04-4955-a6e4-d3af61563b0a",
                    "gracePeriodHours": 144,
                    "actionType": "notification",
                    "notificationTemplateId": "$($MessageTemplateID)",
                    "notificationMessageCCList": []
                },                
                {
                    "id": "fa1d3a8f-9f04-4955-a6e4-d3af61563b0a",
                    "gracePeriodHours": 168,
                    "actionType": "notification",
                    "notificationTemplateId": "$($MessageTemplateID)",
                    "notificationMessageCCList": []
                },                
                {
                    "id": "fa1d3a8f-9f04-4955-a6e4-d3af61563b0a",
                    "gracePeriodHours": 192,
                    "actionType": "notification",
                    "notificationTemplateId": "$($MessageTemplateID)",
                    "notificationMessageCCList": []
                },
                {
                    "id": "6ef5c6d9-7fe7-46be-9c03-23659b9d265a",
                    "gracePeriodHours": 240,
                    "actionType": "notification",
                    "notificationTemplateId": "$($MessageTemplateID)",
                    "notificationMessageCCList": []
                },
                {
                    "id": "17e58653-c4a3-4f1b-9fb5-b5bcbb30e8bb",
                    "gracePeriodHours": 360,
                    "actionType": "notification",
                    "notificationTemplateId": "$($MessageTemplateID)",
                    "notificationMessageCCList": []
                },
                {
                    "id": "7ea10b0b-8fbd-4909-8634-ff7fc49418d6",
                    "gracePeriodHours": 480,
                    "actionType": "notification",
                    "notificationTemplateId": "$($MessageTemplateID)",
                    "notificationMessageCCList": []
                },
                {
                    "id": "8d2886e0-6bb1-4dc7-a94f-9ec94df0ecb4",
                    "gracePeriodHours": 600,
                    "actionType": "notification",
                    "notificationTemplateId": "$($MessageTemplateID)",
                    "notificationMessageCCList": []
                },
                {
                    "id": "061b9592-436c-4daf-a379-c71e15b35e6b",
                    "gracePeriodHours": 624,
                    "actionType": "notification",
                    "notificationTemplateId": "$($MessageTemplateID)",
                    "notificationMessageCCList": []
                },
                {
                    "id": "f1fc15d9-8f68-416b-9838-e267891ccc9e",
                    "gracePeriodHours": 648,
                    "actionType": "notification",
                    "notificationTemplateId": "$($MessageTemplateID)",
                    "notificationMessageCCList": []
                },
                {
                    "id": "b49eeb30-d2a9-422c-8b47-e23b26c9ed97",
                    "gracePeriodHours": 672,
                    "actionType": "notification",
                    "notificationTemplateId": "$($MessageTemplateID)",
                    "notificationMessageCCList": []
                },
                {
                    "id": "e40b0634-6fc9-4cfd-ace0-3c9b06c7f038",
                    "gracePeriodHours": 696,
                    "actionType": "notification",
                    "notificationTemplateId": "$($MessageTemplateID)",
                    "notificationMessageCCList": []
                }
            ]
        }
    ]
}
"@

return $JSON
}

#Get the version numbers
$WindowsVersions = Invoke-GetVersionNumbers

Run theough them and create a policy
foreach($WindowsVersion in $WindowsVersions)
{
    Write-Host "$($WindowsVersion.OS) OS Build $($WindowsVersion.MajorVersion) Version Requirement - 10.0.$($WindowsVersion.Build)"
    $PolicyJson = Invoke-CreateComplianceJSON `
    -description "This policy was Autocreated $(Get-date) and is to require a minimum version number" `
    -displayName "$($WindowsVersion.OS) OS Build $($WindowsVersion.MajorVersion) Version Requirement - 10.0.$($WindowsVersion.Build)" `
    -VersionNumber "10.0.$($WindowsVersion.Build)"

    $graphApiVersion = "v1.0"
    $Resource = "deviceManagement/deviceCompliancePolicies"
    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $(Get-AuthTokenSP) -Method Post -Body $PolicyJson -ContentType "application/json"
}

