import struct, os

class PE32Class():
    def __init__(self):
        pass

    def verifySigDOS(self, pathToFile: str) -> bool:
        """
        Validates the MS-DOS Header signature ('MZ').
        [0x00..0x02] — e_magic (2 bytes, 'MZ' / 0x4D5A)
        """
        try:
            with open(pathToFile, "rb") as f:
                # Read first 2 bytes of the binary
                if(f.read(2) == b"MZ"):
                    return True

        except FileNotFoundError:
            print(f"Error: File {pathToFile} not found.")
            return False
        except IOError:
            print(f"Error reading file {pathToFile}.")
            return False

        return False

    def checkSizeFile(self, pathToFile: str) -> bool:
        """
        Ensures the file size is >= 64 bytes (0x40).
        64 bytes is the minimum size of the MS-DOS Header required to safely read 
        the e_lfanew pointer at offset 0x3C.
        """
        try:
            return os.path.getsize(pathToFile) >= 64
        except OSError:
            return False

    def verifySigPlus(self, pathToFile: str) -> dict:
        """
        Verifies the PE Header signature and determines architecture bitness (PE32 vs PE32+).
        
        Offset Breakdown:
        - 0x3C [4B]: e_lfanew -> File offset pointing to the start of PE Header (pe_offset)
        - pe_offset + 0  [4B]: PE Signature ('PE\x00\x00' / 0x00004550)
        - pe_offset + 4  [20B]: COFF File Header (IMAGE_FILE_HEADER)
        - pe_offset + 24: Start of Optional Header (IMAGE_OPTIONAL_HEADER)
        - pe_offset + 24 + 0 [2B]: Magic number (0x010B = PE32 / 32-bit, 0x020B = PE32+ / 64-bit)
        """
        response = {"status": False, "data": None}
        
        try:
            with open(pathToFile, "rb") as f:
                # 1. Seek to offset 0x3C in DOS Header to retrieve e_lfanew (PE Header pointer)
                f.seek(0x3C)
                pe_offset = struct.unpack('<I', f.read(4))[0]  # <I = uint32 (4 bytes, Little-Endian)

                # 2. Seek to PE Header offset and verify "PE\0\0" signature
                f.seek(pe_offset)
                pe_sig = f.read(4)  # 4 bytes signature
                
                if pe_sig != b'PE\x00\x00':
                    response["data"] = "Invalid PE header signature"
                    return response

                # 3. Calculate Optional Header offset:
                # pe_offset + 4B (PE Signature) + 20B (COFF Header) = pe_offset + 24
                optional_header_offset = pe_offset + 4 + 20
                f.seek(optional_header_offset)

                # 4. Read the first 2 bytes of Optional Header (Magic Number)
                magic = struct.unpack('<H', f.read(2))[0]  # <H = uint16 (2 bytes, Little-Endian)

                # 0x010B = PE32 (32-bit), 0x020B = PE32+ (64-bit / x86_64)
                if magic == 0x010B:
                    response["data"] = "File format is PE32 (32-bit)"
                    return response
                elif magic != 0x020B:
                    response["data"] = f"Unknown format signature: {hex(magic)}"
                    return response

                response["status"] = True
                response["data"] = {
                    "magic": magic,
                    "type": "PE32+",
                    "optional_header_offset": optional_header_offset
                }
                return response
        
        except FileNotFoundError:
            response["data"] = f"Error: File {pathToFile} not found."
            return response
        except IOError:
            response["data"] = f"I/O error while reading file {pathToFile}."
            return response
        except Exception as e:
            response["data"] = f"Unexpected error: {str(e)}"
            return response
            
    def checkCOFFHeader(self, pathToFile: str) -> dict:
        """
        Parses the COFF File Header (IMAGE_FILE_HEADER) which is exactly 20 bytes long.
        
        Relative field offsets from e_lfanew + 4 (skipping 'PE\0\0'):
        - +0x00 [2B] Machine               (0x8664 = x64, 0x014C = x86, 0xAA64 = ARM64)
        - +0x02 [2B] NumberOfSections      (Number of section headers)
        - +0x04 [4B] TimeDateStamp         (UNIX Epoch build timestamp)
        - +0x08 [4B] PointerToSymbolTable  (COFF symbol table offset, 0 for executables)
        - +0x0C [4B] NumberOfSymbols       (Number of symbols in table, 0 for executables)
        - +0x10 [2B] SizeOfOptionalHeader  (Size of Optional Header: 0xE0 for 32-bit, 0xF0 for 64-bit)
        - +0x12 [2B] Characteristics       (Binary attribute flags, e.g., 0x2000 = DLL, 0x0002 = EXE)
        """
        response = {"data": None, "status": False}
        
        with open(pathToFile, "rb") as f:
            # 1. Read e_lfanew offset from DOS Header (0x3C)
            f.seek(0x3C)
            e_lfanew = struct.unpack("<I", f.read(4))[0]

            # 2. Jump to COFF Header (e_lfanew + 4 bytes of PE Signature)
            f.seek(e_lfanew + 4)
            coff_bytes = f.read(20)  # COFF Header size is strictly fixed at 20 bytes
            
            if len(coff_bytes) < 20:
                return response
                
            # 3. Unpack the 20-byte struct:
            # < = Little-Endian
            # H = uint16 (2B), I = uint32 (4B)
            # Format string: H (2B) + H (2B) + I (4B) + I (4B) + I (4B) + H (2B) + H (2B) = 20 Bytes
            machine, sections, timestamp, sym_ptr, sym_num, opt_hdr_size, flags = struct.unpack("<HHIIIHH", coff_bytes)
            
            response["status"] = True
            response["data"] = {
                "Machine": hex(machine),
                "NumberOfSections": sections,
                "TimeDateStamp": timestamp,
                "SizeOfOptionalHeader": opt_hdr_size,
                "Characteristics": hex(flags)
            }
            
        return response