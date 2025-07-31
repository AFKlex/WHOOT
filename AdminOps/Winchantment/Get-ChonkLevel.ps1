function Get-FolderSizes {
    param (
        [string]$DestinationPath = $PWD.Path
    )

    # Function to calculate the size of a folder
    function Get-FolderSize {
        param (
            [string]$Path
        )

        $size = 0
        Get-ChildItem -Path $Path -Recurse -File | ForEach-Object {
            $size += $_.Length
        }
        return $size
    }

    # Function to recursively find all folders with their sizes
    function Get-FolderSizesRecursively {
        param (
            [string]$Path
        )

        Get-ChildItem -Path $Path -Directory | ForEach-Object {
            [PSCustomObject]@{
                FolderPath = $_.FullName
                Size       = (Get-FolderSize -Path $_.FullName)
            }
        }
    }

    # Get all folders with their sizes
    $folders = Get-FolderSizesRecursively -Path $DestinationPath

    # Sort the folders by size in descending order
    $sortedFolders = $folders | Sort-Object -Property Size -Descending

    # Output the sorted list
    if ($sortedFolders) {
        $sortedFolders | ForEach-Object {
            Write-Host "Folder: $($_.FolderPath) - Size: $($_.Size / 1GB) GB"
        }
    } else {
        Write-Host "No folders found."
    }
}

# Call the function with a specified path or use the current PowerShell session's path
# Get-FolderSizes -DestinationPath "D:"
