$word = "devuseonly"
$wordlists = "/usr/share/wordlists"

$files = Get-ChildItem -Path $wordlists -Recurse -Include *.lst,*.txt

foreach ($file in $files) {
    if (Select-String -Path $file.FullName -Pattern $word -Quiet) {
        Write-Host "$word is discoverable within $($file.FullName)"
        $found = $true
        break
    }
}

if (-not $found) {
    Write-Host "$word does not exist in the accessible wordlists"
}