

            [int]$OSBuild = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CurrentBuild
            [string]$OSEditionID = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue |  Select-Object -ExpandProperty EditionID
            [string]$OSProductName =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProductName

            $MachineBuildNumber =  [System.Environment]::OSVersion.VersionString 


            if ((($OSBuild -ge 7601 -and $OSBuild -le 14393) -and ($OSProductName -notmatch 'Windows 10')) -and (($OSEditionID -match 'Enterprise') -or ($OSEditionID -match 'Pro') -or ($OSEditionID -match 'Ultimate') -or ($OSEditionID -match 'Server')))
                # begin Windows 10 downlevel clients or Servers with MMA Agent
                {
                if ((Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "senseId"))
                {
                        $SenseID = (Get-ItemProperty -Path "HKLM:\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\" | Select-Object -ExpandProperty "senseId" )  
                        $MMAService = (Get-Service -Name HealthService -ErrorAction SilentlyContinue).Status
                        $SenseConfigVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "ConfigurationVersion")
                    }
                    else
                    {
                        $OnboardingState = $false
                    }
                 echo "end region Win10 downlevel/serverOS"
                }
            else
                {
                echo " begin Windows native Windows 10 ATP"
                if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\Status" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OnboardingState ) -eq $True)
                    {
                            $OnboardingState = $True
                            $MMAService = "not required"
                            $SenseID = (Get-ItemProperty -Path "HKLM:\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "senseId" )  
                            $SenseConfigVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "ConfigurationVersion" )
                            $MachineIDCalculated = (Get-WinEvent -ProviderName Microsoft-Windows-SENSE | Where-Object -Property Message -Like "*ID calculated*" | Select-Object -L 1).Message 
                            $SenseGUID = (Get-ItemProperty -Path "HKLM:\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection" -ErrorAction SilentlyContinue  | Select-Object -ExpandProperty "senseGuid" )
                            $SenseOrdID = (Get-ItemProperty -Path "HKLM:\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\Status" -ErrorAction SilentlyContinue  | Select-Object -ExpandProperty "OrgID" )
                            $SenseServiceState =  (Get-Service -Name Sense).Status 
                            $DiagTrackServiceState = (Get-Service -Name DiagTrack).Status
                            $DefenderServiceState =  (Get-Service -Name WinDefend).Status 
                            $MSAccountSignInAgentServiceStartType = (Get-Service -Name wlidsvc).StartType 
                            if (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender"  | Select-Object -ExpandProperty "PassiveMode" -ErrorAction SilentlyContinue)
                                    {
                                        $DefenderPassiveMode = $True 
                                    }
                                else
                                    {
                                        $DefenderPassiveMode = $false 
                                    }
                    
                            $DefenderAVSignatureVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Signature Updates" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "AVSignatureVersion" ) 
                            $DefenderEngineVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Signature Updates" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "EngineVersion" ) 

                            $LastConnectedraw =  (Get-ItemProperty -Path "HKLM:\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\Status" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LastConnected ) 
                            $LastSenseTimeStamp = [DateTime]::FromFiletime([Int64]::Parse($LastConnectedraw)) 

                                    if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ReleaseId) -eq 1607 )
                                        {
                                            $DiagTrackLastNormalUploadTimeraw =  (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\SevilleSettings -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LastNormalUploadTime) 
                                            $DiagTrackLastNormalUploadTime = if (-not ($DiagTrackLastNormalUploadTimeraw -eq $null)) { [DateTime]::FromFiletime([Int64]::Parse($DiagTrackLastNormalUploadTimeraw)) } else {"$null"}

                                            $DiagTrackLastRealtimeUploadTimeraw =  (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\SevilleSettings -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LastRealtimeUploadTime) 
                                            $DiagTrackLastRealtimeUploadTime = if (-not ($DiagTrackLastRealtimeUploadTimeraw -eq $null)) { [DateTime]::FromFiletime([Int64]::Parse($DiagTrackLastRealtimeUploadTimeraw)) } else {"$null"}

                                            $DiagTrackLastHeartBeatTimeraw = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\HeartBeats\Seville\ -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LastHeartBeatTime) 
                                            $DiagTrackLastHeartBeatTime = if (-not ($DiagTrackLastHeartBeatTimeraw -eq $null -or $DiagTrackLastHeartBeatTimeraw -eq 0 )) { [DateTime]::FromFiletime([Int64]::Parse($DiagTrackLastHeartBeatTimeraw)) } else {"$null"}

                                            $DiagTrackLastInvalidHttpCode = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\HeartBeats\Seville\ -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LastInvalidHttpCode)  
                                        }
                                    else
                                        {
                                            $DiagTrackLastNormalUploadTimeraw = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\Tenants\P-WDATP -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LastNormalUploadTime )
                                            $DiagTrackLastNormalUploadTime = if (-not ($DiagTrackLastNormalUploadTimeraw -eq $null)) { [DateTime]::FromFiletime([Int64]::Parse($DiagTrackLastNormalUploadTimeraw)) } else {"$null"}

                                            $DiagTrackLastRealtimeUploadTimeraw = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\Tenants\P-WDATP -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LastRealtimeUploadTime) 
                                            $DiagTrackLastRealtimeUploadTime = if (-not ($DiagTrackLastRealtimeUploadTimeraw -eq $null)) { [DateTime]::FromFiletime([Int64]::Parse($DiagTrackLastRealtimeUploadTimeraw)) } else {"$null"}

                                            $DiagTrackLastHeartBeatTimeraw = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\HeartBeats\Seville -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LastHeartBeatTime) 
                                            $DiagTrackLastHeartBeatTime = if (-not ($DiagTrackLastHeartBeatTimeraw -eq $null -or $DiagTrackLastHeartBeatTimeraw -eq 0 )) { [DateTime]::FromFiletime([Int64]::Parse($DiagTrackLastHeartBeatTimeraw)) } else {"$null"}

                                            $DiagTrackLastInvalidHttpCode = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\HeartBeats\Seville -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LastInvalidHttpCode) 
                                    }
                                } 
                    else {
                    $OnboardingState = $false
                    }
            }

            # prepare the output
            $object = [ordered]@{
                "HostName" = $(hostname)
                "OnboardingState" = $OnboardingState
                "OSBuild" = $OSBuild 
                "OSEditionID" = $OSEditionID
                "OSProductName" = $OSProductName 
                "Machinebuildnumber" =  $MachineBuildNumber
                "SenseID" = $SenseID
                "MMAAgentService" =  $MMAService
                "SenseConfigVersion" = $SenseConfigVersion
                "MachineIDCalculated" = $MachineIDCalculated
                "SenseGUID" = $SenseGUID
                "SenseOrdID" = $SenseOrdID
                "SenseServiceState" = $SenseServiceState
                "DiagTrackServiceState" = $DiagTrackServiceState
                "DefenderServiceState" = $DefenderServiceState
                "MSASignInServiceStartup" = $MSAccountSignInAgentServiceStartType
                "DefenderPassiveMode" = $DefenderPassiveMode
                "DefenderAVSignatureVersion" = $DefenderAVSignatureVersion
                "DefenderEngineVersion" = $DefenderEngineVersion
                "LastSenseTimeStamp" =  $LastSenseTimeStamp
                "DiagTrackLastNormalUploadTime" = $DiagTrackLastNormalUploadTime
                "DiagTrackLastRealtimeUploadTime" = $DiagTrackLastRealtimeUploadTime
                "DiagTrackLastHeartBeatTime" = $DiagTrackLastHeartBeatTime
                "DiagTrackLastInvalidHttpCode" = $DiagTrackLastInvalidHttpCode
            }
            $DefenderATPResult = (New-Object -TypeName PSObject -Property $object)
            $DefenderATPResult
