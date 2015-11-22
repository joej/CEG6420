#!/usr/bin/env python
""" generated source for module PEFile """
# package: edu.wright.bryant.util

    
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
        self.offset = 472        #  TODO: get this from where it needs to be set rather than hardcoded

        while i < self.NumberOfSections:
            self.parseImageSectionHeader()
            i += 1

        #  * See https://code.google.com/p/corkami/wiki/PE?show=content#structure_by_structure
        #  get it from the data
        # TODO: Implement section parsing     sections.get(i).parse();
    
    
    
    



    
    
    
    
    # /// PE Data structures and Parsing Routines //////////////
    
    def parseMSDOSStub(self):
        print "\n\n/////MS DOS Header/////"
        e_magic = self.two(0)     #  short MagicNumber        
        print "e_magic \t%x" % e_magic
        e_cparhrd = int()     #  short
        print "e_cparhrd \t%x" % e_cparhrd
        e_lfanew = int()     #  short , required, not sure if 2, 4, or 8 bytes
        print "e_lfanew \t%x" % e_lfanew
        self.OffsetToPESig = self.one(60) #  byte, should be 0xEO in my test.exe
        print "offsetToPESig \t%x" % self.OffsetToPESig


    
    
    
    
    
    
    
    
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
        PESig = self.four(self.OffsetToPESig)
        print "PESig \t%x" % PESig
        self.offset = self.OffsetToPESig + 4
        Machine = self.two(0)   #  TODO: broken, taking wrong values
        print "Machine \t(%d)    %x" % (self.offset, Machine)
        self.NumberOfSections = self.two(2) #  short, null with low alignment PE, up to 96 in XP, 65535 in Vista+
        print "NumberOfSections \t%x" % self.NumberOfSections
        TimeDateStamp = self.four(4) #  different meaning on Borland or MS compiler
        print "TimeDateStamp \t%x" % TimeDateStamp 
        PointerToSymbolTable = self.four(8) #  no importance to loader
        print "PointerToSymbolTable \t%x" % PointerToSymbolTable
        NumberOfSymbols = self.four(12)  # no importance to loader
        print "NumberOfSymbols \t%x" % NumberOfSymbols
        self.SizeOfOptionalHeader = self.two(16)  #  short, delta btw top of opt header and start of sect table
        print "SizeOfOptionalHeader \t%x" % self.SizeOfOptionalHeader
        #  Characteristics: short, 014c for 32b, 8664 for 64b (not req'd if no code executes (data only))
         #  short, 0x2 IMAGE_FILE_EXECUTABLE_IMAGE req'd to exec code
        #  0x2000 / IMAGE_FILE_DLL req'd for dlls (to call DLLMain), dll and exports still usable, imports not resolved
        #  0x100 / IMAGE_FILE_32BIT_MACHINE not req'd, nothing else req'd
        #  11111111 11111111 
        Characteristics = self.two(18)
        print "Characteristics \t%d    %x" % (self.offset+18, Characteristics)












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
        self.offset = self.offset+20  # sets this up for the right location from COFF offset  
        Magic = self.two(0)  #  short, exact format for OptionalHeader 10b for 32b, 20b for 64b
        print "Magic \t(%d)      %x" % (self.offset, Magic)
        MajorLinkerVersion = self.one(2)  #  byte, >= 2.5
        print "MajorLinkerVersion \t%d" % MajorLinkerVersion
        MinorLinkerVersion = self.one(3)  #  byte
        print "MinorLinkerVersion \t%d" % MinorLinkerVersion
        SizeOfCode = self.four(4)  #  not important
        print "SizeOfCode \t%x" % SizeOfCode
        SizeOfInitializedData = self.four(8)  #  ni
        print "SizeOfInitializedData \t%x" % SizeOfInitializedData
        SizeOfUninitializedData = self.four(12)  # ni
        print "SizeOfUninitializedData \t%x" % SizeOfUninitializedData
        AddressOfEntryPoint = self.four(16)  #  <= SizeOfHeaders | null (dlls that don't call dllmain)
        #  can be absent (TLS), can be negative, virtual
        print "AddressOfEntryPoint \t%x" % AddressOfEntryPoint
        BaseOfCode = self.four(20)  # ni
        print "BaseOfCode \t%x" % BaseOfCode
        BaseOfData = self.four(24)  # ni
        print "BaseOfData \t%x" % BaseOfData










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
        #  TODO: Handle PE32+ mode offsets
        ImageBase = self.four(28)          #  mult of 10000h, can be null in xp (->10000h)
        #  ImageBase + SizeOfImage < 80000000h; can't collide with ntdll or kernel32
        print "ImageBase \t(%d)     %x" % (self.offset+28, ImageBase)
        SectionAlignment = self.four(32) #  pow of 2
        print "SectionAlignment \t%x" % SectionAlignment
        FileAlignment = self.four(36) #  pow of 2, std mode 200 <= FileAlignment <= sectionAlignment => 1000
        print "FileAlignment \t%d" % FileAlignment
        MajorOperatingSystemVersion = self.two(40)
        print "MajorOperatingSystemVersion \t%x" % MajorOperatingSystemVersion
        MinorOperatingSystemVersion = self.two(42)
        print "MinorOperatingSystemVersion \t%x" % MinorOperatingSystemVersion
        MajorImageVersion = self.two(46)
        print "MajorImageVersion \t%x" % MajorImageVersion
        MinorImageVersion = self.two(46)
        print "MinorImageVersion \t%x" % MinorImageVersion
        MajorSubsystemVersion = self.two(48) #  short, >= 3.10 to 6.30
        print "MajorSubsystemVersion \t%x" % MajorSubsystemVersion
        MinorSubsystemVersion = self.two(50)
        print "MinorSubsystemVersion \t%x" % MinorSubsystemVersion
        Win32VersionValue = self.four(52) #  reserved -> null, messes w/ versions
        print "Win32VersionValue \t%x" % Win32VersionValue
        SizeOfImage = self.four(56) #  total virt size of all sections+headers
        print "SizeOfImage \t%x" % SizeOfImage
        self.SizeOfHeaders = self.four(60)  #  can be extended to whole file or smaller than header
        print "SizeOfHeaders \t(%d)   %x" % (self.offset+60, self.SizeOfHeaders)
        CheckSum = self.four(64)  #  reqd for drivers only
        print "CheckSum \t%x" % CheckSum
        Subsystem = self.two(68)
        print "Subsystem \t%x" % Subsystem
        DllCharacteristics = self.two(70) #  short, driver need low alignments, correct checksum, signed under vista or later
        #  console PE = GUI PE except comes with pre-attached console
        #  determines level of execution by checking CS
        #  resolve ntoskrnl/kernel32 imports manually (by checksum)
        #  short, 0080h forces dll signing
        #  0x0100 prevents code execution on stack
        #  0400 prevents exec to use SEH, but VEH still works
        #  1000 used only by Metro in Win 8
        #  4000 controlflow guard in win8
        print "DllCharacteristics \t%x" % DllCharacteristics
        SizeOfStackReserve = self.four(72)  # can be zero, same as below
        print "SizeOfStackReserve \t%x" % SizeOfStackReserve
        SizeOfStackCommit = self.four(76)
        print "SizeOfStackCommit \t%x" % SizeOfStackCommit
        SizeOfHeapReserve = self.four(80)
        print "SizeOfHeapReserve \t%x" % SizeOfHeapReserve
        SizeOfHeapCommit = self.four(84)
        print "SizeOfHeapCommit \t%x" % SizeOfHeapCommit
        LoaderFlags = self.four(88)
        print "LoaderFlags \t%x" % LoaderFlags
        NumberOfRvaAndSizes = self.four(92)         # rounded down to 16 if bigger, can be 0, .Net loaders ignore this
        print "NumberOfRvaAndSizes \t%x" % NumberOfRvaAndSizes
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        













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
        ExportTable = self.four(96)
        ExportTableSize = self.four(100)
        print "ExportTable \t%x    size = %x" % (ExportTable, ExportTableSize)
        ImportTable = self.four(104)
        ImportTableSize = self.four(108)        
        print "ImportTable \t%x  size = %x" % (ImportTable, ImportTableSize)
        ResourceTable = self.four(112)
        ResourceTableSize = self.four(116)
        print "ResourceTable \t%x    size = %x" % (ResourceTable, ResourceTableSize)
        ExceptionTable = self.four(120)
        ExceptionTableSize = self.four(124)
        print "ExceptionTable \t%x    size = %x" % (ExceptionTable, ExceptionTableSize)
        CertificateTable = self.four(128)
        CertificateTableSize = self.four(132)
        print "CertificateTable \t%x    size = %x" % (CertificateTable, CertificateTableSize)
        BaseRelocationTable = self.four(136)
        BaseRelocationTableSize = self.four(140)
        print "BaseRelocationTable \t%x    size = %x" % (BaseRelocationTable, BaseRelocationTableSize)
        DebugTable = self.four(144)
        DebugTableSize = self.four(148)
        print "DebugTable \t%x    size = %x" % (DebugTable, DebugTableSize)
        Architecture = self.four(152)
        ArchitectureSize = self.four(156)
        print "Architecture \t%x    size = %x" % (Architecture, ArchitectureSize)
        GlobalPtr = self.four(160)
        GlobalPtrSize = self.four(164)
        print "GlobalPtr \t%x    size = %x" % (GlobalPtr, GlobalPtrSize)
        TLSTable = self.four(168)
        TLSTableSize = self.four(172)
        print "TLSTable \t%x    size = %x" % (TLSTable, TLSTableSize)
        LoadConfigTable = self.four(176)
        LoadConfigTableSize = self.four(180)
        print "LoadConfigTable \t%x    size = %x" % (LoadConfigTable, LoadConfigTableSize)
        BoundImportTable = self.four(184)
        BoundImportTableSize = self.four(188)
        print "BoundImportTable \t%x    size = %x" % (BoundImportTable, BoundImportTableSize)
        IAT = self.four(192)
        IATSize = self.four(196)
        print "IAT \t%x     size = %x" % (IAT, IATSize)
        DelayImportDescriptor = self.four(200)
        DelayImportDescriptorSize = self.four(204)
        print "DelayImportDescriptor \t%x    size = %x" % (DelayImportDescriptor, DelayImportDescriptorSize)
        CLRRuntimeHeader = self.four(208)
        CLRRuntimeHeaderSize = self.four(212)
        print "CLRRuntimeHeader \t%x     size = %x" % (CLRRuntimeHeader, CLRRuntimeHeaderSize)
        Reserved = self.eight(216)
        print "Reserved \t%s" % Reserved

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
        print "VirtualSize \t%d"% VirtualSize
        VirtualAddress = self.four(12)
        print "VirtualAddress \t%x"% VirtualAddress
        SizeOfRawData = self.four(16)
        print "SizeOfRawData \t%d"% SizeOfRawData
        PointerToRawData = self.four(20)
        print "PointerToRawData \t%x"% PointerToRawData
        PointerToRelocations = self.four(24)
        print "PointerToRelocations \t%x"% PointerToRelocations
        PointerToLinenumbers = self.four(28)
        print "PointerToLineNumbers \t%x"% PointerToLinenumbers
        NumberOfRelocations = self.two(32)
        print "NumberOfRelocations \t%d"% NumberOfRelocations
        NumberOfLinenumbers = self.two(34)
        print "NumberOfLineNumbers \t%d"% NumberOfLinenumbers
        Characteristics = self.four(36)
        print "Characteristics \t%x"% Characteristics
        self.offset = self.offset + 40


        
        
    # //////////
    def one(self, j):
        j += self.offset
#        print "    %d"% j
        return self.PE[j]
    
    def two(self, i):
#        print "two(%d)" % i 
        if self.littleEndian:
            result = self.one(i + 1) << 8 | self.one(i)
            return result
        result = self.one(i) << 8 | self.one(i + 1)
        return result
    
    def four(self, i):
#        print "four(%d)" % i
        result = 0
        if self.littleEndian:
            result = (self.one(i + 3) << 24 | self.one(i + 2) << 16 | self.one(i + 1) << 8 | self.one(i))
            return result
        result = self.one(i) << 24 | self.one(i + 1) << 16 | self.one(i + 2) << 8 | self.one(i + 3)
        return result  #  TODO: Need to fix this mess
    
    def eight(self, i):
#        print "eight(%d)"% i
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
    @classmethod
    def main(cls, args):
        f_name = "Module2Binary.exe"
        f = open(f_name, "rb")
        p = PEFile(f)


if __name__ == '__main__':
    import sys
    RESim.main(sys.argv)
    

