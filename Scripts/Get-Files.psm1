function Get-Files {
    param (
        [Parameter(Mandatory)][string]$Path
    )
    $files = Get-ChildItem $Path
    $Collection_Files = New-Object System.Collections.Generic.List[System.Object]
    foreach ($file in $files) {
        if ($file.Length -eq 1) {
            $type            = "Directory"
            $ChildItem       = Get-ChildItem -Path $file.FullName -Recurse -ErrorAction Ignore
            $size            = ($ChildItem | Measure-Object -Property Length -Sum).Sum/1gb
            $size            = [string]([double]::Round($size, 3))+" GB"
            $Files_Count     = $ChildItem | Where-Object { $_.PSIsContainer -eq $false }
            $Directory_Count = $ChildItem | Where-Object { $_.PSIsContainer -eq $true }
        } else {
            $type            = "File"
            $size            = $file.Length / 1gb
            $size            = [string]([double]::Round($size, 3))+" GB"
        }
        $Collection_Files.Add([PSCustomObject]@{
            Name           = $file.Name
            FullName       = $file.FullName
            Type           = $type
            Size           = $size
            Files          = $Files_Count.Count
            Directory      = $Directory_Count.Count
            CreationTime   = Get-Date -Date $file.CreationTime -Format "dd/MM/yyyy hh:mm:ss"
            LastAccessTime = Get-Date -Date $file.LastAccessTime -Format "dd/MM/yyyy hh:mm:ss"
            LastWriteTime  = Get-Date -Date $file.LastWriteTime -Format "dd/MM/yyyy hh:mm:ss"
        })
    }
    $Collection_Files
}

# Get-Files -Path "C:/"
# Get-Files -Path "C:/Program Files/"
# Get-Files -Path "D:/"
# Get-Files -Path "D:/Movies/"