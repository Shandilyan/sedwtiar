[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$appRoot = Split-Path -Parent $PSCommandPath
$launcher = Join-Path $appRoot 'launch_sedwtiar.vbs'
$iconPng = Join-Path $appRoot 'icon.png'
$appIconPng = Join-Path $appRoot 'app_icon.png'
$iconIco = Join-Path $appRoot 'sedwtiar-logo.ico'
$desktop = [Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory)
$shortcutPath = Join-Path $desktop 'SEDWTIAR Desktop.lnk'

foreach ($requiredFile in @($launcher, $iconPng)) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        throw "Required SEDWTIAR launcher file is missing: $requiredFile"
    }
}

# Build a real multi-size .ico. Icon.FromHandle().Save() writes a broken icon
# that Explorer shows as a blank page, so the shortcut stays empty.
Add-Type -AssemblyName System.Drawing

function Get-LogoBounds {
    param([System.Drawing.Bitmap]$Bitmap)
    $width = $Bitmap.Width
    $height = $Bitmap.Height
    $area = New-Object System.Drawing.Rectangle 0, 0, $width, $height
    $locked = $Bitmap.LockBits($area, [System.Drawing.Imaging.ImageLockMode]::ReadOnly, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    try {
        $stride = $locked.Stride
        $pixels = New-Object byte[] ($stride * $height)
        [System.Runtime.InteropServices.Marshal]::Copy($locked.Scan0, $pixels, 0, $pixels.Length)
    } finally {
        $Bitmap.UnlockBits($locked)
    }

    $minX = $width
    $minY = $height
    $maxX = -1
    $maxY = -1
    for ($y = 0; $y -lt $height; $y++) {
        $row = $y * $stride
        for ($x = 0; $x -lt $width; $x++) {
            $index = $row + ($x * 4)
            $blue = $pixels[$index]
            $green = $pixels[$index + 1]
            $red = $pixels[$index + 2]
            $alpha = $pixels[$index + 3]
            if ($alpha -gt 16 -and ($red -lt 245 -or $green -lt 245 -or $blue -lt 245)) {
                if ($x -lt $minX) { $minX = $x }
                if ($y -lt $minY) { $minY = $y }
                if ($x -gt $maxX) { $maxX = $x }
                if ($y -gt $maxY) { $maxY = $y }
            }
        }
    }

    if ($maxX -lt 0) {
        return $area
    }

    $padX = [Math]::Max(8, [int](($maxX - $minX + 1) * 0.06))
    $padY = [Math]::Max(8, [int](($maxY - $minY + 1) * 0.06))
    $left = [Math]::Max(0, $minX - $padX)
    $top = [Math]::Max(0, $minY - $padY)
    $right = [Math]::Min($width - 1, $maxX + $padX)
    $bottom = [Math]::Min($height - 1, $maxY + $padY)
    return New-Object System.Drawing.Rectangle $left, $top, ($right - $left + 1), ($bottom - $top + 1)
}

function Save-PngIcon {
    param(
        [System.Drawing.Image]$Image,
        [int[]]$Sizes,
        [string]$Path
    )
    $pngImages = New-Object System.Collections.Generic.List[byte[]]
    foreach ($size in $Sizes) {
        $frame = New-Object System.Drawing.Bitmap $size, $size
        try {
            $graphics = [System.Drawing.Graphics]::FromImage($frame)
            try {
                $graphics.Clear([System.Drawing.Color]::White)
                $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
                $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
                $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
                $graphics.DrawImage($Image, (New-Object System.Drawing.Rectangle 0, 0, $size, $size))
            } finally {
                $graphics.Dispose()
            }
            $memory = New-Object System.IO.MemoryStream
            try {
                $frame.Save($memory, [System.Drawing.Imaging.ImageFormat]::Png)
                $pngImages.Add($memory.ToArray())
            } finally {
                $memory.Dispose()
            }
        } finally {
            $frame.Dispose()
        }
    }

    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create)
    try {
        $writer = New-Object System.IO.BinaryWriter($stream, [System.Text.Encoding]::UTF8, $true)
        try {
            $writer.Write([uint16]0)
            $writer.Write([uint16]1)
            $writer.Write([uint16]$pngImages.Count)
            $offset = 6 + (16 * $pngImages.Count)
            for ($index = 0; $index -lt $pngImages.Count; $index++) {
                $dimension = $Sizes[$index]
                $storedDimension = if ($dimension -ge 256) { [byte]0 } else { [byte]$dimension }
                $writer.Write($storedDimension)
                $writer.Write($storedDimension)
                $writer.Write([byte]0)
                $writer.Write([byte]0)
                $writer.Write([uint16]1)
                $writer.Write([uint16]32)
                $writer.Write([uint32]$pngImages[$index].Length)
                $writer.Write([uint32]$offset)
                $offset += $pngImages[$index].Length
            }
            foreach ($png in $pngImages) {
                $writer.Write($png)
            }
            $writer.Flush()
        } finally {
            $writer.Dispose()
        }
    } finally {
        if ($stream.CanWrite) {
            $stream.Dispose()
        }
    }
}

$source = [System.Drawing.Bitmap]::FromFile($iconPng)
try {
    $bounds = Get-LogoBounds -Bitmap $source
    $side = [Math]::Max($bounds.Width, $bounds.Height)
    $square = New-Object System.Drawing.Bitmap $side, $side
    try {
        $graphics = [System.Drawing.Graphics]::FromImage($square)
        try {
            $graphics.Clear([System.Drawing.Color]::White)
            $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
            $drawX = [int](($side - $bounds.Width) / 2)
            $drawY = [int](($side - $bounds.Height) / 2)
            $graphics.DrawImage(
                $source,
                (New-Object System.Drawing.Rectangle $drawX, $drawY, $bounds.Width, $bounds.Height),
                $bounds,
                [System.Drawing.GraphicsUnit]::Pixel
            )
        } finally {
            $graphics.Dispose()
        }

        $square.Save($appIconPng, [System.Drawing.Imaging.ImageFormat]::Png)
        $iconSizes = @(256, 128, 64, 48, 32, 24, 16)
        Save-PngIcon -Image $square -Sizes $iconSizes -Path $iconIco
        Save-PngIcon -Image $square -Sizes $iconSizes -Path (Join-Path $appRoot 'icon.ico')
    } finally {
        $square.Dispose()
    }
} finally {
    $source.Dispose()
}

$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = Join-Path $env:SystemRoot 'System32\wscript.exe'
$shortcut.Arguments = '"' + $launcher + '"'
$shortcut.WorkingDirectory = $appRoot
$shortcut.IconLocation = $iconIco + ',0'
$shortcut.Description = 'Launch SEDWTIAR Desktop Asset Assurance'
$shortcut.Save()

if (-not ('Sedwtiar.ShellNotify' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SedwtiarShellNotify {
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    public static extern void SHChangeNotify(int eventId, uint flags, string item1, IntPtr item2);
}
'@
}
# SHCNE_UPDATEITEM = 0x2000, SHCNF_PATHW = 0x5. Refresh this shortcut only.
[SedwtiarShellNotify]::SHChangeNotify(0x2000, 0x5, $shortcutPath, [IntPtr]::Zero)
[SedwtiarShellNotify]::SHChangeNotify(0x2000, 0x5, $iconIco, [IntPtr]::Zero)

Write-Host "Desktop shortcut created: $shortcutPath"
