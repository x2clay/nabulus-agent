# Dedicated Qwen2.5-Coder-14B on the Tailscale address.
# Threads stay at 4. The 20-thread launch burned tokens/sec on this box.
$ErrorActionPreference = 'Stop'
$root = 'C:\Users\Laith\llama-cpp'
Get-Content "$root\server.env" | Where-Object { $_ -match '^\s*[^#]\S*=' } | ForEach-Object {
    $k, $v = $_ -split '=', 2
    $v = ($v -split '\s+#', 2)[0]
    Set-Item -Path "Env:$($k.Trim())" -Value $v.Trim()
}
$exe = Join-Path $root 'bin\llama-server.exe'
$model = Join-Path $root 'models\qwen2.5-coder-14b-instruct\Qwen2.5-Coder-14B-Instruct-Q4_K_M.gguf'
if (-not (Test-Path $model)) { throw "missing $model" }
$listen = (tailscale ip -4 | Select-Object -First 1).Trim()
if (-not $listen) { throw 'no tailscale ipv4' }
New-Item -ItemType Directory -Force "$root\logs" | Out-Null
Get-NetTCPConnection -LocalPort 8081 -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
    Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
}
$args = @(
    '--model', $model,
    '--alias', 'qwen2.5-coder-14b',
    '--host', $listen,
    '--port', '8081',
    '--api-key', $env:LLAMA_API_KEY,
    '--ctx-size', '16384',
    '--parallel', '1',
    '--n-gpu-layers', '99',
    '--flash-attn', 'on',
    '--cache-type-k', 'q8_0',
    '--cache-type-v', 'q8_0',
    '--threads', '4',
    '--threads-batch', '4',
    '--jinja'
)
$p = Start-Process -FilePath $exe -ArgumentList $args -WorkingDirectory "$root\bin" -WindowStyle Hidden `
    -RedirectStandardOutput "$root\logs\coder14.out.log" -RedirectStandardError "$root\logs\coder14.err.log" -PassThru
Set-Content "$root\logs\coder14.pid" $p.Id
$envFile = 'C:\Users\Laith\nabulus-agent\local.env'
@(
    "LLAMA_BASE=http://${listen}:8081/v1",
    "LLAMA_MODEL=qwen2.5-coder-14b",
    "LLAMA_API_KEY=$($env:LLAMA_API_KEY)"
) | Set-Content $envFile -Encoding ascii
Write-Output "STARTED pid=$($p.Id) listen=${listen}:8081"
