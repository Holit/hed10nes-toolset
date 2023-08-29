
Write-Host "变更网络配置..."

# 确认管理员权限
$isAdmin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()) | ForEach-Object {
    $_.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not $isAdmin) {
    Write-Host "脚本需要管理员权限才能运行，请以管理员身份重新运行脚本。"
    Write-Host "网络配置未变更"
    return
}

# 定义需要设置的参数值
$ipAddress = "192.168.1.100"
$subnetMask = "255.255.255.0"
$gateway = "192.168.1.1"
$dnsServers = "8.8.8.8.", "4.4.4.4"

# 获取适配器对象
$adapter = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {
    $_.IPEnabled -eq $true -and $_.Description -like "*Ethernet*" -and $_.Description -notlike "*Virtual*"
}

# 记录当前配置
$oldIPAddress = $adapter.IPAddress[0]
$oldSubnetMask = $adapter.IPSubnet[0]
$oldGateway = $adapter.DefaultIPGateway
$oldDNSServers = $adapter.DNSServerSearchOrder

Try {
	# 设置IP地址、子网掩码和网关
	Write-Host "正在配置IP地址和子网掩码..."	
	$null = $adapter.EnableStatic($ipAddress, $subnetMask)
	Write-Host "正在配置网关..."	
	$null = $adapter.SetGateways($gateway, 1)

	# 设置DNS服务器
	Write-Host "正在配置DNS服务器..."	
	$null = $adapter.SetDNSServerSearchOrder($dnsServers)
} Catch {
    Write-Host "发生错误，开始回滚。 $_.Exception.Message"
	$null = $adapter.EnableStatic($oldIPAddress, $oldSubnetMask)
	$null = $adapter.SetGateways($oldGateway, 1)
	$null = $adapter.SetDNSServerSearchOrder($oldDNSServers)
}
# 显示配置前后的数据
Write-Host "-------------------------"
Write-Host "适配器信息："
Write-Host "IP地址:`t`t$oldIPAddress`t-> $ipAddress"
Write-Host "子网掩码:`t$oldSubnetMask`t-> $subnetMask"
Write-Host "网关:`t`t$oldGateway`t-> $gateway"
Write-Host "DNS服务器:`t$oldDNSServers`t-> $dnsServers"

Write-Host ""
Write-Host "IPv4配置已成功更改。"
