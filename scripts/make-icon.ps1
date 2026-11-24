<#
.SYNOPSIS
  Regenerates the RDP Monitor icon: assets\rdpmon.ico (16-256 px) and
  assets\rdpmon.png (256 px, used for the configuration window).

  The icon is drawn as vectors at every size, so small sizes stay sharp:
  a display on a blue tile with a green "pulse" line (live monitoring).
  The generated files are committed; run this only to change the design.
#>
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing
$root = Split-Path -Parent $PSScriptRoot
$assets = Join-Path $root "assets"
New-Item -ItemType Directory -Force $assets | Out-Null

function New-RoundedRect([single]$x, [single]$y, [single]$w, [single]$h, [single]$r) {
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = 2 * $r
    $p.AddArc($x, $y, $d, $d, 180, 90)
    $p.AddArc($x + $w - $d, $y, $d, $d, 270, 90)
    $p.AddArc($x + $w - $d, $y + $h - $d, $d, $d, 0, 90)
    $p.AddArc($x, $y + $h - $d, $d, $d, 90, 90)
    $p.CloseFigure()
    $p
}

function New-IconPng([int]$s) {
    $bmp = New-Object System.Drawing.Bitmap($s, $s, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = "AntiAlias"
    $g.PixelOffsetMode = "HighQuality"
    $g.Clear([System.Drawing.Color]::Transparent)
    $u = $s / 32.0   # design grid: 32 x 32

    # Tile
    $tile = New-RoundedRect (0.5 * $u) (0.5 * $u) (31 * $u) (31 * $u) (6 * $u)
    $grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        (New-Object System.Drawing.PointF(0, 0)), (New-Object System.Drawing.PointF(0, $s)),
        [System.Drawing.Color]::FromArgb(255, 37, 99, 235), [System.Drawing.Color]::FromArgb(255, 30, 58, 138))
    $g.FillPath($grad, $tile)

    # Display: white bezel, dark screen
    $white = [System.Drawing.Color]::White
    $bezel = New-RoundedRect (5 * $u) (6.5 * $u) (22 * $u) (15 * $u) (2 * $u)
    $g.FillPath((New-Object System.Drawing.SolidBrush($white)), $bezel)
    $screen = New-RoundedRect (6.8 * $u) (8.3 * $u) (18.4 * $u) (11.4 * $u) (0.8 * $u)
    $g.FillPath((New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 15, 23, 42))), $screen)

    # Stand
    $wb = New-Object System.Drawing.SolidBrush($white)
    $g.FillRectangle($wb, [single](14 * $u), [single](21.5 * $u), [single](4 * $u), [single](2.8 * $u))
    $g.FillPath($wb, (New-RoundedRect (10 * $u) (24 * $u) (12 * $u) (2.2 * $u) (1.1 * $u)))

    # Pulse line
    $w = [Math]::Max(1.2, 1.6 * $u)
    $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(255, 34, 197, 94), [single]$w)
    $pen.LineJoin = "Round"; $pen.StartCap = "Round"; $pen.EndCap = "Round"
    $pts = @(
        @(8.3, 14.6), @(12.3, 14.6), @(14.0, 10.6), @(16.6, 18.0), @(18.4, 13.0), @(19.6, 14.6), @(23.7, 14.6)
    ) | ForEach-Object { New-Object System.Drawing.PointF([single]($_[0] * $u), [single]($_[1] * $u)) }
    $g.DrawLines($pen, [System.Drawing.PointF[]]$pts)

    $g.Dispose()
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    , $ms.ToArray()
}

# ICO with PNG-encoded entries (supported by Windows Vista and later).
$sizes = 16, 20, 24, 32, 40, 48, 64, 256
$images = foreach ($s in $sizes) { , (New-IconPng $s) }
$out = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter($out)
$bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $s = $sizes[$i]; $len = $images[$i].Length
    $dim = if ($s -ge 256) { 0 } else { $s }
    $bw.Write([byte]$dim); $bw.Write([byte]$dim); $bw.Write([byte]0); $bw.Write([byte]0)
    $bw.Write([uint16]1); $bw.Write([uint16]32); $bw.Write([uint32]$len); $bw.Write([uint32]$offset)
    $offset += $len
}
foreach ($img in $images) { $bw.Write([byte[]]$img) }
$bw.Flush()
[System.IO.File]::WriteAllBytes((Join-Path $assets "rdpmon.ico"), $out.ToArray())
[System.IO.File]::WriteAllBytes((Join-Path $assets "rdpmon.png"), $images[-1])
Write-Host "Wrote $assets\rdpmon.ico and rdpmon.png"
