param(
    [Parameter(Mandatory = $true)][string]$Source,
    [Parameter(Mandatory = $true)][string]$Output,
    [Parameter(Mandatory = $true)][ValidateSet("x86_64", "aarch64")][string]$Architecture
)

$ErrorActionPreference = "Stop"
$expected = "286762b7730e2b780678f5ab11fef2b1bad639e0"
$dynamicName = "symcrypt_zig_103_13"
if ($Architecture -eq "x86_64") {
    $upstreamArch = "amd64"
    $flavor = "amd64fre"
    $target = "x86_64-windows-msvc"
} else {
    $upstreamArch = "arm64"
    $flavor = "arm64fre"
    $target = "aarch64-windows-msvc"
}

$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio/Installer/vswhere.exe"
$toolComponent = if ($Architecture -eq "x86_64") {
    "Microsoft.VisualStudio.Component.VC.Tools.x86.x64"
} else {
    "Microsoft.VisualStudio.Component.VC.Tools.ARM64"
}
$installation = & $vswhere -latest -products * `
    -requires $toolComponent `
    -property installationPath
if (-not $installation) {
    throw "Visual Studio with the MSVC toolchain was not found"
}
$developerArchitecture = if ($Architecture -eq "x86_64") { "amd64" } else { "arm64" }
. (Join-Path $installation "Common7/Tools/Launch-VsDevShell.ps1") `
    -Arch $developerArchitecture -SkipAutomaticLocation

if ((git -C $Source rev-parse "HEAD^{commit}") -ne $expected) {
    throw "expected SymCrypt commit $expected"
}
if ((git -C $Source rev-parse "v103.13.0^{commit}") -ne $expected) {
    throw "v103.13.0 does not resolve to the pinned commit"
}
$version = Get-Content (Join-Path $Source "version.json") -Raw | ConvertFrom-Json
if ($version.major -ne 103 -or $version.minor -ne 13 -or $version.patch -ne 0) {
    throw "expected SymCrypt version 103.13.0"
}
$gitlink = (git -C $Source ls-tree HEAD 3rdparty/jitterentropy-library).Split()[2]
if ($gitlink -ne "887c9871ea110e397812ff7f3b28a6269f0a2ffc") {
    throw "unexpected Jitterentropy gitlink $gitlink"
}
if (git -C $Source status --porcelain --untracked-files=no) {
    throw "SymCrypt source has tracked modifications before fixture build"
}

$project = Join-Path $Source "modules/windows/user/symcrypt.vcxproj"
$definition = Join-Path $Source "modules/windows/user/symcrypt.def"
try {
    $projectText = Get-Content $project -Raw
    $projectText = $projectText.Replace(
        "<TargetName>symcrypt</TargetName>",
        "<TargetName>$dynamicName</TargetName>"
    )
    Set-Content $project $projectText -NoNewline
    $definitionText = Get-Content $definition -Raw
    $definitionText = $definitionText.Replace(
        "NAME symcrypt.dll",
        "NAME $dynamicName.dll"
    )
    Set-Content $definition $definitionText -NoNewline

    python (Join-Path $Source "scripts/build.py") msbuild `
        --arch $upstreamArch `
        --config Release
    if ($LASTEXITCODE -ne 0) {
        throw "pinned SymCrypt MSBuild failed with exit code $LASTEXITCODE"
    }
} finally {
    git -C $Source checkout -- modules/windows/user/symcrypt.vcxproj modules/windows/user/symcrypt.def
}

$base = Join-Path $Source "build/bin/$flavor"
$dllDir = Join-Path $base "dll"
$libDir = Join-Path $base "lib"
$paths = @{
    Dll = Join-Path $dllDir "$dynamicName.dll"
    Import = Join-Path $dllDir "$dynamicName.lib"
    Static = Join-Path $libDir "symcrypt_static_NoCIL.lib"
    Plus = Join-Path $libDir "symcrypt_plus_NoCIL.lib"
}
foreach ($path in $paths.Values) {
    if (-not (Test-Path $path -PathType Leaf)) {
        throw "missing expected $target SymCrypt artifact: $path"
    }
}

New-Item -ItemType Directory -Force -Path $Output | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Output "dll") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Output "lib") | Out-Null
Copy-Item $paths.Dll (Join-Path $Output "dll/$dynamicName.dll")
Copy-Item $paths.Import (Join-Path $Output "dll/$dynamicName.lib")
Copy-Item $paths.Static (Join-Path $Output "lib/symcrypt_static_NoCIL.lib")
Copy-Item $paths.Plus (Join-Path $Output "lib/symcrypt_plus_NoCIL.lib")

python (Join-Path $PSScriptRoot "fixture_manifest.py") create `
    --root $Output `
    --source $Source `
    --target $target `
    --library "dynamic:plus:$(Join-Path $Output 'lib/symcrypt_plus_NoCIL.lib')" `
    --library "dynamic:core:$(Join-Path $Output "dll/$dynamicName.lib")" `
    --library "static:plus:$(Join-Path $Output 'lib/symcrypt_plus_NoCIL.lib')" `
    --library "static:core:$(Join-Path $Output 'lib/symcrypt_static_NoCIL.lib')"
if ($LASTEXITCODE -ne 0) {
    throw "fixture provenance generation failed"
}

Write-Output "dll_dir=$((Resolve-Path (Join-Path $Output 'dll')).Path)"
Write-Output "provenance=$((Resolve-Path (Join-Path $Output 'provenance.json')).Path)"
