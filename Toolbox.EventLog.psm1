Function Grant-WritePermissionsEventLogHC {
    <#
        .SYNOPSIS
            Add write permissions to a Windows Event Log for an AD object.

        .PARAMETER Account
            Active directory object that needs write permissions.

        .PARAMETER LogName
            Name of the log where we grant permissions

        .EXAMPLE
            ./script.ps! -Account 'Domain users' -LogName Application
    #>

    Param (
        [String]$Account = 'Domain users',
        [String]$LogName = 'HCScripts'
    )

    $AdObj = New-Object System.Security.Principal.NTAccount($Account)
    $SID = $AdObj.Translate([System.Security.Principal.SecurityIdentifier])

    $w = wevtutil gl $LogName
    $channelAccess = $w[5]

    if ($channelAccess.Contains('channelAccess:')) {

        $str = $channelAccess.Replace('channelAccess: ', '')

        if ($str.Contains($SID.Value) -eq $false) {
            $newstr = $str + "(A;;0x3;;;" + $SID.Value + ")"
            wevtutil sl $LogName /ca:$newstr
            wevtutil gl $LogName
            Write-Verbose "Granted write permissions to the Windows Event Log for '$Account' on log '$LogName'"
        }
        else {
            Write-Verbose "Windows Event Log permissions are correct"
        }
    }
}

Function Import-EventLogParamsHC {
    <#
    .SYNOPSIS
        Import all the parameters for writing to the event log.

    .DESCRIPTION
        Import all the necessary parameters for writing to the event log. The 
        use of this function will allow standardization in the Windows Event Log
        by using the same EventID's and other properties across different 
        scripts.

        Custom Windows EventID's based on the PowerShell standard streams:

        PowerShell Stream     EventIcon    EventID   EventDescription
        -----------------     ---------    -------   ----------------
                              [i] Info     100       Script started
        [4] Verbose           [i] Info     4         Verbose message
        [1] Output/Success    [i] Info     1         Output on success
                              [i] Info     199       Script ended successfully
        [3] Warning           [w] Warning  3         Warning message
        [2] Error             [e] Error    2         Fatal error message

    .PARAMETER Source
        Specifies the script name under which the events will be logged.

    .EXAMPLE
        $ScriptName = 'Test'
        Import-EventLogParamsHC -Source $ScriptName
        Write-EventLog @EventStartParams
        Write-EventLog @EventVerboseParams -Message 'This is a verbose message'
        Write-EventLog @EventOutParams -Message 'Send e-mail to the user'
        Write-EventLog @EventEndParams

        Writes the start and end time to the Windows Event Log together with
        information from the verbose and output stream.
    #>

    [CmdLetBinding()]
    [OutputType()]
    Param (
        [Parameter(Mandatory)]
        [String]$Source,
        [String]$LogName = 'HCScripts'
    )

    if (
        -not(
            ([System.Diagnostics.EventLog]::Exists($LogName)) -and
            [System.Diagnostics.EventLog]::SourceExists($Source)
        )
    ) {
        New-EventLog -LogName $LogName -Source $Source -ErrorAction Stop
    }

    $EventParams = @{
        LogName     = $LogName
        Source      = $Source
        ErrorAction = 'Stop'
    }
    $Global:EventStartParams = $EventParams + @{
        EntryType = 'Information'
        EventID   = '100'
        Message   = ($env:USERNAME + ' - ' + 'Script started')
    }
    $Global:EventEndParams = $EventParams + @{
        EntryType = 'Information'
        EventID   = '199'
        Message   = ($env:USERNAME + ' - ' + 'Script ended')
    }
    $Global:EventVerboseParams = $EventParams + @{ 
        EntryType = 'Information'
        EventID   = '4' 
    }
    $Global:EventOutParams = $EventParams + @{ 
        EntryType = 'Information'
        EventID   = '1' 
    }
    $Global:EventWarnParams = $EventParams + @{ 
        EntryType = 'Warning'
        EventID   = '3' 
    }
    $Global:EventErrorParams = $EventParams + @{ 
        EntryType = 'Error'
        EventID   = '2' 
    }
}

Export-ModuleMember -Function * -Alias *