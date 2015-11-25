#!/usr/bin/env python
""" generated source for module PEFile """
# package: edu.wright.bryant.util

from collections import OrderedDict

# 
#  * See https://code.google.com/p/corkami/wiki/PE?show=content#structure_by_structure
#  * @author adambryant

#       # TODO: parse the file
		# TODO: find out how sections are aligned
		# TODO: capture the executable sections
		# TODO: disassemble the code

#  

class PEFile():


	def __init__(self, f):
		i = 0
		self.SectionsStart = 0
		self.offset = 0   # type, name, value, location
		self.littleEndian = True
		self.PE = bytearray(f.read())
		f.close()

		self.parseMSDOSStub()
		self.parseCOFFFileHeader()
		self.parseOptionalHeader()
		self.parseOptionalHeaderWindowsFields()
		self.parseOptionalHeaderDataDirectories()

		#  get it from the data
		#  * See https://code.google.com/p/corkami/wiki/PE?show=content#structure_by_structure
		#  get it from the data

		# -- should be checking/failing if 0
		print
		print '%s' %  '-' * 60
		self.offset = self.SectionsStart
		print "Ready to process %02X (%d) SECTIONS @ %08X (%d)" % \
			(self.NumberOfSections, self.NumberOfSections, 
			self.offset, self.offset)
		print '%s' %  '-' * 60
		print

		while i < self.NumberOfSections:
			self.parseImageSectionHeader()
			i += 1

		#  * See https://code.google.com/p/corkami/wiki/PE?show=content#structure_by_structure
		#  get it from the data
		# TODO: Implement section parsing     sections.get(i).parse();


	# -- starting at the current offset, parse the 64-byte/40H IMAGE_DOS_HEADER
	def parseMSDOSStub(self):
		print "\n\n/////MS DOS Header/////"

		d = OrderedDict()
		d['e_magic'] = 2        # 2 = WORD
		d['e_cblp'] = 2
		d['e_cp'] = 2
		d['e_crlc'] = 2
		d['e_cparhdr'] = 2
		d['e_minalloc'] = 2
		d['e_maxalloc'] = 2
		d['e_ss'] = 2
		d['e_sp'] = 2
		d['e_csum'] = 2
		d['e_ip'] = 2
		d['e_cs'] = 2
		d['e_lfarlc'] = 2
		d['e_ovno'] = 2
		d['e_res1'] = 8        # 4 reserved WORDS
		d['e_oemid'] = 2
		d['e_oeminfo'] = 2
		d['e_res2'] = 20        # 10 reservied WORDS
		d['e_lfanew'] = 4

		self.offset = 0			# lets specicically set this properly
		print "Current self.offset is %04X (%d)" % (self.offset, self.offset)
		i = 0
		for k in d.keys():
			if d[k] == 2:
				s = self.two(i)
				print "%16s:\t%04X" % (k, s)
				i = i + 2
			elif d[k] == 4:
				s = self.four(i)
				print "%16s:\t%08X" % (k, s)
				i = i + 4
			else:
				# - output sets of 2/DWORDS ... assuming even numbers
				for ii in range(0, d[k], 2):
					print "%16s:\t%04X" % (k, self.two(i + ii) )
					ii = ii + 2
				i = i + d[k]


		#e_magic = self.two(0)     #  short MagicNumber        
		#print "e_magic \t%4x" % e_magic
		#e_cparhrd = int()     #  short 
		#print "e_cparhrd \t%x" % e_cparhrd
		#e_lfanew = int()     #  short , required, not sure if 2, 4, or 8 bytes
		#print "e_lfanew \t%x" % e_lfanew

		self.OffsetToPESig = self.one(60) #  byte, should be 0xEO in my test.exe
		print "offsetToPESig \t%08X" % self.OffsetToPESig

		print "Section addresses: %08X -- %08X\t[+%04X (%d)]" % (self.offset, self.offset + i, i, i)





	# 
	#      * // start COFF File Header (obj and image) idx 0 => PE_sig+4    
	#         0        2    Machine (4C 01)
	#         2        2    NumberOfSections (07 00)
	#         4        4    TimeDateStamp (32 1a 92 4d)
	#         8        4    PointerToSymbolTable (00 00 00 00)
	#         12        4    NumberOfSymbols (00 00 00 00)
	#         16        2    SizeOfOptionalHeader (E0 00)
	#         18        2    Characteristics (02 01)
	#         

	def parseCOFFFileHeader(self):
		print "\n\n///// COFF File Header /////"

		# -- bump the self.offset up to this header, now
		self.offset = self.OffsetToPESig
		print "Current self.offset is %04X (%d)" % (self.offset, self.offset)

		# -- read the first 4 WORDS of this header
		PESig = self.four(0)
		print "PESig \t%08X" % PESig

		# -- Now, start into the FILE_HEADER section
		self.offset = self.offset + 4
		print "Current self.offset is %04X (%d)" % (self.offset, self.offset)
		i = 0

		Machine = self.two(i)
		print "Machine \t%08X (%d)    %04X" % (self.offset + i, self.offset + i, Machine)
		i = i + 2

		self.NumberOfSections = self.two(i) #  short, null with low alignment PE, up to 96 in XP, 65535 in Vista+
		print "NumberOfSections \t%04X" % self.NumberOfSections
		i = i + 2

		TimeDateStamp = self.four(i) #  different meaning on Borland or MS compiler
		print "TimeDateStamp \t%08X" % TimeDateStamp 
		i = i + 4

		PointerToSymbolTable = self.four(i) #  no importance to loader
		print "PointerToSymbolTable \t%08X" % PointerToSymbolTable
		i = i +  4

		NumberOfSymbols = self.four(i)  # no importance to loader
		print "NumberOfSymbols \t%08X" % NumberOfSymbols
		i = i + 4

		self.SizeOfOptionalHeader = self.two(i)  #  short, delta btw top of opt header and start of sect table
		print "SizeOfOptionalHeader \t%04X" % self.SizeOfOptionalHeader
		i = i + 2

		#  Characteristics: short, 014c for 32b, 8664 for 64b (not req'd if no code executes (data only))
		#  short, 0x2 IMAGE_FILE_EXECUTABLE_IMAGE req'd to exec code
		#  0x2000 / IMAGE_FILE_DLL req'd for dlls (to call DLLMain), dll and exports still usable, imports not resolved
		#  0x100 / IMAGE_FILE_32BIT_MACHINE not req'd, nothing else req'd
		#  11111111 11111111 
		Characteristics = self.two(i)
		print "Characteristics \t(%d)    %04X" % (self.offset+18, Characteristics)
		i = i + 2

		print "Section addresses: %08X -- %08X\t[+%04X (%d)]" % (self.offset-4, self.offset + i, i, i)

	# 
	#      * // Optional Header (PE32/PE32+) (image only) (byte 248 on mine)
	#         0        2        Magic 0x10B = exec, 0x107 = ROM, 0x20B = PE32+ (0B 01)
	#         2        1        MajorLinkerVersion (09)
	#         3        1        MinorLinerVersion (00)
	#         4        4        SizeOfCode (text section, sum of all) (00 60 00 00)
	#         8        4        SizeOfInitializedData (sum of all) (00 42 00 00)
	#         12        4        SizeOfUnititalizedData (BSS or sum of all) (00 00 00 00)
	#         16        4        AddressOfEntryPoint (rel to imageBase) (9f 11 01 00)
	#         20        4        BaseOfCode        (.text section, rel to ImageBase) (00 10 00 00)
	#         24        4        BaseOfData (beg of data section rel to ImageBase) (00 00 40 00)
	#      

	def parseOptionalHeader(self): 

		print "\n\n///// Optional Header /////" 

		i = 0
		self.offset = self.offset + 20		# previous COFF header was 20 
		print "Current self.offset is %04X (%d)" % (self.offset, self.offset)

		Magic = self.two(i)  #  short, exact format for OptionalHeader 10b for 32b, 20b for 64b
		print "Magic \t(%d)      %04X" % (self.offset, Magic)
		i = i + 2

		MajorLinkerVersion = self.one(i)  #  byte, >= 2.5
		print "MajorLinkerVersion \t%d" % MajorLinkerVersion
		i = i + 1

		MinorLinkerVersion = self.one(i)  #  byte
		print "MinorLinkerVersion \t%d" % MinorLinkerVersion
		i = i + 1

		SizeOfCode = self.four(i)  #  not important
		print "SizeOfCode \t%x" % SizeOfCode
		i = i + 4

		SizeOfInitializedData = self.four(i)  #  ni
		print "SizeOfInitializedData \t%x" % SizeOfInitializedData
		i = i + 4

		SizeOfUninitializedData = self.four(i)  # ni
		print "SizeOfUninitializedData \t%x" % SizeOfUninitializedData
		i = i + 4

		AddressOfEntryPoint = self.four(i)  #  <= SizeOfHeaders | null (dlls that don't call dllmain)
		#  can be absent (TLS), can be negative, virtual
		print "AddressOfEntryPoint \t%x" % AddressOfEntryPoint
		i = i + 4

		BaseOfCode = self.four(i)  # ni
		print "BaseOfCode \t%x" % BaseOfCode
		i = i + 4

		BaseOfData = self.four(i)  # ni
		print "BaseOfData \t%x" % BaseOfData
		i = i + 4

		print "Section addresses: %08X -- %08X\t[+%04X (%d)]" % (self.offset, self.offset + i, i, i)





	# 
	#  Optional Header Windows-specific fields (image only) (byte 280 on mine) PE32/PE32+
	#     28/24    4/8        ImageBase (pref addr of first byte of image, multiple of 64K (0x00400000) (00 10 00 00)
	#     32/32    4        SectionAlignment (in bytes, def is page size) (00 02 00 00)
	#     36/36    4        FileAlignment (power of 2 {512 - 64K})(must be leq SecAlignment) (05 00 00 00)
	#     40/40    2        MajorOperatingSystemVersion (00 00)
	#     42/42    2        MinorOperatingSystemVersion (00 00)
	#     44/44    2        MajorImageVersion (05 00)
	#     46/46    2        MinorImageVersion (00 00)
	#     48/48    2        MajorSubsystemVersion (00 00)
	#     50/50    2        MinorSubsystemVersion (00 00)
	#     52/52    4        Win32VersionValue (reserved, must be zero) (00 f0)
	#     56/56    4        SizeOfImage (in bytes, all headers. mult of SectionAlignment)
	#     60/60    4        SizeOfHeaders (combined size of msdos, peh, sech, rounded up to mult of FileAlignment)
	#     64/64    4        CheckSum
	#     68/68    2        Subsystem
	#     70/70    2        DllCharacteristics
	#     72/72    4/8        SizeOfStackReserve
	#     76/80    4/8        SizeOfStackCommitt
	#     80/88    4/8        SizeOfHeapReserve
	#     84/96    4/8        SizeOfHeapCommit
	#     88/104    4        LoaderFlags (must be zero)
	#     92/108    4        NumberOfRvaAndSizes
	#     


	def parseOptionalHeaderWindowsFields(self):

		print "\n\n///// Optional Header Windows Fields /////"

		i = 0
		self.offset = self.offset + 28	# previous section was 28 in size
		print "Current self.offset is %04X (%d)" % (self.offset, self.offset)

		#  TODO: Handle PE32+ mode offsets
		ImageBase = self.four(i)          #  mult of 10000h, can be null in xp (->10000h)

		#  ImageBase + SizeOfImage < 80000000h; can't collide with ntdll or kernel32
		print "ImageBase \t(%d)     %04X" % (self.offset, ImageBase)
		i = i + 4

		SectionAlignment = self.four(i) #  pow of 2
		print "SectionAlignment \t%08x" % SectionAlignment
		i = i + 4

		FileAlignment = self.four(i) #  pow of 2, std mode 200 <= FileAlignment <= sectionAlignment => 1000
		print "FileAlignment \t%08X (%d)" % (FileAlignment, FileAlignment)
		i = i + 4

		MajorOperatingSystemVersion = self.two(i)
		print "MajorOperatingSystemVersion \t%04x" % MajorOperatingSystemVersion
		i = i + 2

		MinorOperatingSystemVersion = self.two(i)
		print "MinorOperatingSystemVersion \t%04x" % MinorOperatingSystemVersion
		i = i + 2

		MajorImageVersion = self.two(i)
		print "MajorImageVersion \t%04x" % MajorImageVersion
		i = i + 2

		MinorImageVersion = self.two(i)
		print "MinorImageVersion \t%04x" % MinorImageVersion
		i = i + 2

		MajorSubsystemVersion = self.two(i) #  short, >= 3.10 to 6.30
		print "MajorSubsystemVersion \t%04x" % MajorSubsystemVersion
		i = i + 2

		MinorSubsystemVersion = self.two(i)
		print "MinorSubsystemVersion \t%04x" % MinorSubsystemVersion
		i = i + 2

		Win32VersionValue = self.four(i) #  reserved -> null, messes w/ versions
		print "Win32VersionValue \t%08x" % Win32VersionValue
		i = i + 4

		SizeOfImage = self.four(i) #  total virt size of all sections+headers
		print "SizeOfImage \t%08x" % SizeOfImage
		i = i + 4

		self.SizeOfHeaders = self.four(i)  #  can be extended to whole file or smaller than header
		print "SizeOfHeaders \t(%d)   %08x" % (self.offset+60, self.SizeOfHeaders)
		i = i + 4

		CheckSum = self.four(i)  #  reqd for drivers only
		print "CheckSum \t%08x" % CheckSum
		i = i + 4

		Subsystem = self.two(i)
		print "Subsystem \t%04x" % Subsystem
		i = i + 2

		DllCharacteristics = self.two(i) #  short, driver need low alignments, correct checksum, signed under vista or later
		i = i + 2

		#  console PE = GUI PE except comes with pre-attached console
		#  determines level of execution by checking CS
		#  resolve ntoskrnl/kernel32 imports manually (by checksum)
		#  short, 0080h forces dll signing
		#  0x0100 prevents code execution on stack
		#  0400 prevents exec to use SEH, but VEH still works
		#  1000 used only by Metro in Win 8
		#  4000 controlflow guard in win8
		print "DllCharacteristics \t%x" % DllCharacteristics

		SizeOfStackReserve = self.four(i)  # can be zero, same as below
		print "SizeOfStackReserve \t%08x" % SizeOfStackReserve
		i = i + 4

		SizeOfStackCommit = self.four(i)
		print "SizeOfStackCommit \t%08x" % SizeOfStackCommit
		i = i + 4

		SizeOfHeapReserve = self.four(i)
		print "SizeOfHeapReserve \t%08x" % SizeOfHeapReserve
		i = i + 4

		SizeOfHeapCommit = self.four(i)
		print "SizeOfHeapCommit \t%08x" % SizeOfHeapCommit
		i = i + 4

		LoaderFlags = self.four(i)
		print "LoaderFlags \t%08x" % LoaderFlags
		i = i + 4

		NumberOfRvaAndSizes = self.four(i)         # rounded down to 16 if bigger, can be 0, .Net loaders ignore this
		print "NumberOfRvaAndSizes \t%08x" % NumberOfRvaAndSizes
		i = i + 4

		print "Section addresses: %08X -- %08X\t[+%04X (%d)]" % (self.offset, self.offset + i, i, i)



# 
#  Optional Header data directories (image only)
#     96/112    8        Export Table (address and size) .edata
#     104/120    8        Import Table (addr and size) .idata
#     112/128    8        Resource Table (addr, size) .rsrc
#     120/136    8        Exception Table (addr, size) .pdata
#     128/144    8        Certificate Table (addr, size) 
#     136/152    8        Base relocation table (addr, size) .reloc
#     144/160    8        Debug (starting addr and size) .debug
#     152/168    8        Architecture (must be zero)
#     160/176    8        Global Ptr    (rva of val to store in global ptr register (addr, zero)
#     168/184    8        TLS Table (addr, size) .tls
#     176/192    8        Load Config Table
#     184/200    8        Bound Import
#     192/208    8        IAT    
#     200/216    8        Delay Import Descriptor
#     208/224    8        CLR Runtime Header .cormeta
#     216/232    8        Reserved (zero)
#     

	def parseOptionalHeaderDataDirectories(self):

		print "\n\n///// Optional Header Data Directories /////"

		i = 0
		self.offset = self.offset +  68		# previous sect, optional windows headers = 68 
		print "Current self.offset is %04X (%d)" % (self.offset, self.offset)

		ExportTable = self.four(i)
		ExportTableSize = self.four(i+4)
		print "%20s:\t%08X\tsize = %08X (%d)" % \
			("ExportTable", ExportTable, ExportTableSize, ExportTableSize)
		#print "ExportTable \t%x    size = %x" % (ExportTable, ExportTableSize)
		i = i + 8

		ImportTable = self.four(i)
		ImportTableSize = self.four(i+4)
		#print "ImportTable \t%x  size = %x" % (ImportTable, ImportTableSize)
		print "%20s:\t%08X\tsize = %08X (%d)" % \
			("ImportTable", ImportTable, ImportTableSize, ImportTableSize)
		i = i + 8

		ResourceTable = self.four(i)
		ResourceTableSize = self.four(i+4)
		#print "ResourceTable \t%x    size = %x" % (ResourceTable, ResourceTableSize)
		print "%20s:\t%08X\tsize = %08X (%d)" % \
			("ResourceTable", ResourceTable, ResourceTableSize, ResourceTableSize)
		i = i + 8

		ExceptionTable = self.four(i)
		ExceptionTableSize = self.four(i+4)
		#print "ExceptionTable \t%x    size = %x" % (ExceptionTable, ExceptionTableSize)
		print "%20s:\t%08X\tsize = %08X (%d)" % \
			("ExceptionTable", ExceptionTable, ExceptionTableSize, ExceptionTableSize)
		i = i + 8

		CertificateTable = self.four(i)
		CertificateTableSize = self.four(i+4)
		#print "CertificateTable \t%x    size = %x" % (CertificateTable, CertificateTableSize)
		print "%20s:\t%08X\tsize = %08X (%d)" % \
			("CertificateTable", CertificateTable, CertificateTableSize, CertificateTableSize)
		i = i + 8

		BaseRelocationTable = self.four(i)
		BaseRelocationTableSize = self.four(i+4)
		#print "BaseRelocationTable \t%x    size = %x" % (BaseRelocationTable, BaseRelocationTableSize)
		print "%20s:\t%08X\tsize = %08X (%d)" % \
			("BaseRelocationTable", BaseRelocationTable, BaseRelocationTableSize, BaseRelocationTableSize)
		i = i + 8

		DebugTable = self.four(i)
		DebugTableSize = self.four(i+4)
		#print "DebugTable \t%x    size = %x" % (DebugTable, DebugTableSize)
		print "%20s:\t%08X\tsize = %08X (%d)" % \
			("DebugTable", DebugTable, DebugTableSize, DebugTableSize)
		i = i + 8

		Architecture = self.four(i)
		ArchitectureSize = self.four(i+4)
		#print "Architecture \t%x    size = %x" % (Architecture, ArchitectureSize)
		print "%20s:\t%08X\tsize = %08X (%d)" % \
			("Architecture", Architecture, ArchitectureSize, ArchitectureSize)
		i = i + 8

		GlobalPtr = self.four(i)
		GlobalPtrSize = self.four(i+4)
		#print "GlobalPtr \t%x    size = %x" % (GlobalPtr, GlobalPtrSize)
		print "%20s:\t%08X\tsize = %08X (%d)" % \
			("GlobalPtr", GlobalPtr, GlobalPtrSize, GlobalPtrSize)
		i = i + 8

		TLSTable = self.four(i)
		TLSTableSize = self.four(i+4)
		#print "TLSTable \t%x    size = %x" % (TLSTable, TLSTableSize)
		print "%20s:\t%08X\tsize = %08X (%d)" % \
			("TLSTable", TLSTable, TLSTableSize, TLSTableSize)
		i = i + 8

		LoadConfigTable = self.four(i)
		LoadConfigTableSize = self.four(i+4)
		#print "LoadConfigTable \t%x    size = %x" % (LoadConfigTable, LoadConfigTableSize)
		print "%20s:\t%08X\tsize = %08X (%d)" % \
			("LoadConfigTable", LoadConfigTable, LoadConfigTableSize, LoadConfigTableSize)
		i = i + 8

		BoundImportTable = self.four(i)
		BoundImportTableSize = self.four(i+4)
		#print "BoundImportTable \t%x    size = %x" % (BoundImportTable, BoundImportTableSize)
		print "%20s:\t%08X\tsize = %08X (%d)" % \
			("BoundImportTable", BoundImportTable, BoundImportTableSize, BoundImportTableSize)
		i = i + 8

		IAT = self.four(i)
		IATSize = self.four(i+4)
		#print "IAT \t%x     size = %x" % (IAT, IATSize)
		print "%20s:\t%08X\tsize = %08X (%d)" % \
			("IAT", IAT, IATSize, IATSize)
		i = i + 8

		DelayImportDescriptor = self.four(i)
		DelayImportDescriptorSize = self.four(i+4)
		#print "DelayImportDescriptor \t%x    size = %x" % (DelayImportDescriptor, DelayImportDescriptorSize)
		print "%20s:\t%08X\tsize = %08X (%d)" % \
			("DlyImportDescriptor", DelayImportDescriptor, DelayImportDescriptorSize, DelayImportDescriptorSize)
		i = i + 8

		CLRRuntimeHeader = self.four(i)
		CLRRuntimeHeaderSize = self.four(i+4)
		#print "CLRRuntimeHeader \t%x     size = %x" % (CLRRuntimeHeader, CLRRuntimeHeaderSize)
		print "%20s:\t%08X\tsize = %08X (%d)" % \
			("CLRRuntimeHeader", CLRRuntimeHeader, CLRRuntimeHeaderSize, CLRRuntimeHeaderSize)
		i = i + 8

		Reserved = self.eight(i)
		#print "Reserved \t%s" % Reserved
		print "%20s:\t%016X" % ("Reserved", Reserved)
		i = i + 8

		# -- we'll need this address to process the various SECTIONS
		self.SectionsStart = self.offset + i

		print "Section addresses: %08X -- %08X\t[+%04X (%d)]" % (self.offset, self.offset + i, i, i)

	def parseExportsTable(self):
		""" generated source for class ExportsTable """

	def parseImportsTable(self):
		""" generated source for class ImportsTable """

	def parseImportLookupTable(self):
		""" generated source for class ImportLookupTable """

	def parseIAT(self):
		""" generated source for class IAT """

	def parseResourcesTable(self):
		""" generated source for class ResourcesTable """












# 
#  Section Table (section headers)
#     0        8        Name (UTF-8) (zero padded)
#     8        4        VirtualSize (if greater than SizeOfRawData, zero padded)
#     12        4        VirtualAddress (addr of first byte of section, rel to ImageBase)
#     16        4        SizeOfRawData (size of section or init data, mult of fileAlignment, if < VirtualSize, zero padded
#     20        4        PointerToRawData (first page of section) aligned to FileAlignment
#     24        4        PointerToRelocations (zero for executable images)
#     28        4        PointerToLinenumbers (zero)
#     32        2        NumberOfRelocations (zero for exec)
#     34        2        NumberOfLinenumbers (zero for image)
#     36        4        Characteristics (flags)
#     

	def parseImageSectionHeader(self):

		print "\n\n///// Image Section Header /////"

		self.littleEndian = False
		Name = self.eightString(0)

		self.littleEndian = True
		print "Name \t(%d)     %s"% (self.offset, Name)

		VirtualSize = self.four(8)
		print "VirtualSize \t%08X (%d)" % (VirtualSize, VirtualSize)

		VirtualAddress = self.four(12)
		print "VirtualAddress \t%08X (%d)" % (VirtualAddress, VirtualAddress)

		SizeOfRawData = self.four(16)
		print "SizeOfRawData \t%08X (%d)" % (SizeOfRawData, SizeOfRawData)

		PointerToRawData = self.four(20)
		print "PointerToRawData \t%08X (%d)" % (PointerToRawData, PointerToRawData)

		PointerToRelocations = self.four(24)
		print "PointerToRelocations \t%08X (%d)" % (PointerToRelocations, PointerToRelocations)

		PointerToLinenumbers = self.four(28)
		print "PointerToLineNumbers \t%08X (%d)" % (PointerToLinenumbers, PointerToLinenumbers)

		NumberOfRelocations = self.two(32)
		print "NumberOfRelocations \t%04X (%d)" % (NumberOfRelocations, NumberOfRelocations)

		NumberOfLinenumbers = self.two(34)
		print "NumberOfLineNumbers \t%04X (%d)" % (NumberOfLinenumbers, NumberOfLinenumbers)

		Characteristics = self.four(36)
		print "Characteristics \t%08X (%d)" % (Characteristics, Characteristics)

		self.offset = self.offset + 40

		print "Section addresses: %08X -- %08X\t[+%04X (%d)]" % (self.offset - 40, self.offset, 40, 40) 


	# //////////
	def one(self, j):            # -- at location OFFSET + j, read one WORD
		j += self.offset
		#print "    %d"% j
		return self.PE[j]

	def two(self, i):            # -- at location i, read 2
		#print "two(%d)" % i 
		if self.littleEndian:
			result = self.one(i + 1) << 8 | self.one(i)
			return result
		result = self.one(i) << 8 | self.one(i + 1)
		return result

	def four(self, i):            # -- at location i, read 4
		#print "four(%d)" % i
		result = 0
		if self.littleEndian:
			result = (self.one(i + 3) << 24 | self.one(i + 2) << 16 | self.one(i + 1) << 8 | self.one(i))
			return result
		result = self.one(i) << 24 | self.one(i + 1) << 16 | self.one(i + 2) << 8 | self.one(i + 3)
		return result  #  TODO: Need to fix this mess

	def eight(self, i):            # -- get 8 one()s from location i (from offset pointer)
		#print "eight(%d)"% i
		if self.littleEndian:
			result = self.one(i) | self.one(i + 1) << 8 | self.one(i + 2) << 16 | self.one(i + 3) << 24 | self.one(i + 4) << 32 | self.one(i + 5) << 40 | self.one(i + 6) << 48 | self.one(i + 7) << 56
			return result
		result = self.one(i) << 56 | self.one(i) << 48 | self.one(i) << 40 | self.one(i) << 32 | self.one(i) << 24 | self.one(i) << 16 | self.one(i) << 8 | self.one(i)
		return result

	def eightString(self, i):
		i += self.offset
		PE = self.PE
		bytes = [PE[i], PE[i+1], PE[i+2], PE[i+3], PE[i+4], PE[i+5], PE[i+6], PE[i+7]]
		return "".join(map(chr, bytes)) 







	# /////////////
	def toUInt(self, signedInt):
		if signedInt > -1:
			return signedInt
		else:
			print "toUInt: " + ((signedInt) & 0xFFFFFFFF) + " " + "index: " + offset
			return (signedInt & 0xFFFFFFFF)  #  only works for smaller ints            

	def toUShort(self, signedShort):
		if signedShort > -1:
			return signedShort
		else:
			print "toUbyte: " + (signedShort & 0xFFFF) + " " + "index: " + offset
			return (signedShort) & 0xFFFF   #  only works for smaller longs

	def toUByte(self, signedByte):
		if signedByte > -1:
			return signedByte
		else:
			print "toUbyte: " + (signedByte & 0xFF) + " " + "index: " + offset
			return (signedByte & 0xFF)

	def toULong(self, signedLong):
		if signedLong > -1:
			return signedLong
		else:
			print "toULong: " + (signedLong & 0xFFFFFFFF) + " " + "index: " + offset
			return (signedLong) & 0xFFFFFFFF   #  only works for smaller longs




class RESim():
	#  @param args 
	@classmethod            # decorator
	def main(cls, args):
		f_name = "Module2Binary.exe"
		f = open(f_name, "rb")
		p = PEFile(f)


if __name__ == '__main__':
	import sys
	RESim.main(sys.argv)


