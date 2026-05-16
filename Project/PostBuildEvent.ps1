param (
	[string]$vsProjektDir,
	[string]$vsBuildOption
)

$moduleManifestName = "Send-MailKitMessage.psd1"
$ExampleFileName    = "Example-Send-MailKitMessage.ps1"
$vsBinFolder        = "bin\$vsBuildOption\net9.0"

$PostBuildBannerStarted = @"
=========================================
              [PostBuild]
        PostBuild Process Started!
=========================================

"@

$PostBuildBannerFinished = @"
=========================================
              [PostBuild]
     PostBuild Process Complete!
=========================================

"@

$vsProjektDir  = $vsProjektDir.Trim("'")
$vsBuildOption = $vsBuildOption.Trim("'")

if (-not $vsProjektDir -or -not $vsBuildOption) {
	Write-Error "ProjektDir or BuildOption is missing."
	exit 1
}

Write-Host $PostBuildBannerStarted -ForegroundColor Cyan
Write-Host "PowerShell Version : $($PSVersionTable.PSVersion.ToString())" -ForegroundColor Gray
Write-Host "Project Dir        : $vsProjektDir"                           -ForegroundColor Gray

$projectRoot     = Split-Path $vsProjektDir
$moduleManifest  = Join-Path $vsProjektDir $moduleManifestName
$ExampleFile     = Join-Path $vsProjektDir $ExampleFileName
$buildOutputPath = Join-Path $vsProjektDir $vsBinFolder
$moduleLocation  = Join-Path $projectRoot "Module"

if (-not $buildOutputPath.EndsWith('\*')) {
	$buildOutputPath = $buildOutputPath + '\*'
}

Write-Host "Build Output       : '$buildOutputPath'" -ForegroundColor Gray
Write-Host "Module Manifest    : '$moduleManifest'"  -ForegroundColor Gray
Write-Host "Module Destination : '$moduleLocation'"  -ForegroundColor Gray
Write-Host ""

if (-not (Test-Path $moduleManifest -ErrorAction Stop)) {
	Write-Error "PowerShell module manifest '$moduleManifestName' not found."
	exit 1
}

try {
	if (Test-Path $moduleLocation) {
		Write-Host "Clearing $moduleLocation ..." -ForegroundColor Yellow
		Get-ChildItem $moduleLocation | Remove-Item -Recurse -Force
	}

	if (-not (Test-Path $moduleLocation)) {
		Write-Host "Creating folder $moduleLocation ..." -ForegroundColor Yellow
		$null = New-Item $moduleLocation -ItemType Directory -ErrorAction Stop
	}

	Copy-Item -Path $buildOutputPath  -Destination $moduleLocation -Recurse -ErrorAction Stop
	Copy-Item -Path $moduleManifest   -Destination $moduleLocation -Force   -ErrorAction Stop
	Copy-Item -Path $ExampleFile      -Destination $moduleLocation -Force   -ErrorAction SilentlyContinue
}
catch {
	Write-Error $_
	exit 1
}

Write-Host "Module successfully built at '$moduleLocation'" -ForegroundColor Green
Write-Host $PostBuildBannerFinished -ForegroundColor Cyan
