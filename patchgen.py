import re
import idaapi
import idc
import ida_bytes
# RunPlugin("patchgen", 0)

class patchgen(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "This is a comment"
    help = "Press Alt-F8 to generate the patch code."
    wanted_name = "patchgen"
    wanted_hotkey = "Alt-F8"

    def init(self):
        print("[+] PatchGen plugin loaded. Press %s to generate the patch code." % patchgen.wanted_hotkey)
        return idaapi.PLUGIN_OK

    def run(self, arg):
        self.print_patches(self.get_patched_bytes())

    def get_patched_bytes(self, start=None, end=None):
        if start is None:
            start = idaapi.cvar.inf.min_ea
        if end is None:
            end = idaapi.cvar.inf.max_ea

        patched_bytes = dict()

        def collector(ea, fpos, original, patched):
            patched_bytes[ea] = PatchData(ea, fpos, original, patched)
            return 0

        idaapi.visit_patched_bytes(start, end, collector)
        return patched_bytes
    
    def h(self, num):
        # print('0x{0:08X}'.format(ida_loader.get_fileregion_offset(ScreenEA())))
        return '0x{:08X}'.format(num)
    
    def h_bytes(self, bytes):
        return ", ".join("0x{:02X}".format(x) for x in bytes)
    
    def group_patches(self, patches):
        last_addr = 0
        current_group = PatchGroup()
        
        patch_groups = []
        sorted_addresses = sorted(patches.keys()) # Dictionaries aren't sorted by default
        for addr in sorted_addresses:
            if addr > last_addr + 1 and current_group.length() > 0:
                # Not in sequence:
                patch_groups.append(current_group)
                current_group = PatchGroup()

            bytePatch = patches[addr]
            current_group.append(bytePatch)
            last_addr = addr
        
        if current_group.length() > 0:
            # The last group:
            patch_groups.append(current_group)
        return patch_groups
    
    def print_patches(self, patches):
        patch_groups = self.group_patches(patches)

        print()
        print("/" * 20 + " %d Patches " % (len(patch_groups)) + "/" * 20)
        print()
        for chunk in patch_groups:
            patched_instructions = " | ".join(chunk.disasm_patched())
            original_instructions = " | ".join(chunk.disasm_original())

            patch_descr = "// %s(): [%s]  ==>  [%s]" % (chunk.func_name(), original_instructions, patched_instructions)
            print(patch_descr)

            fpos_str = self.h(chunk.fpos())
            orig_str = self.h_bytes(chunk.original())
            patch_str = self.h_bytes(chunk.patched())

            # print "%s: %s => %s" % (fpos_str, orig_str, patch_str)
            
            if chunk.length() == 1:
                print("Hunks.Add(new SinglePatchHunk(%s, %s, %s));" % (fpos_str, orig_str, patch_str))
            else:
                print("Hunks.Add(new SinglePatchHunk(%s, new byte[] { %s }, new byte[] { %s }));" % (fpos_str, orig_str, patch_str))
            print()

    
    def term(self):
        pass


class PatchData:
    def __init__(self, ea, fpos, original, patched):
        self.ea = ea
        self.fpos = fpos
        self.original = original
        self.patched = patched


class PatchGroup:
    def __init__(self):
        self.bytes = []
    
    def append(self, byte_patch):
        self.bytes.append(byte_patch)

    def ea(self):
        return self.bytes[0].ea

    def fpos(self):
        return self.bytes[0].fpos

    def func_name(self):
        return idaapi.get_func_name(self.ea())

    def length(self):
        return len(self.bytes)
    
    def disasm_patched(self):
        result = []
    
        offset = 0
        while True:
            if offset >= self.length():
                break
            instruction_addr = self.ea() + offset
            disasm = idc.GetDisasm(instruction_addr)
            disasm = re.sub("\\s+", " ", disasm)
            result.append(disasm)
            
            offset += ida_bytes.get_item_size(instruction_addr)
        return result
    
    def disasm_original(self):
        self.revert_patch()
        disasm = self.disasm_patched()
        self.apply_patch()
        return disasm
    
    def revert_patch(self):
        for b in self.bytes:
            ida_bytes.patch_byte(b.ea, b.original)

    def apply_patch(self):
        for b in self.bytes:
            ida_bytes.patch_byte(b.ea, b.patched)

    def original(self):
        return map(lambda b: b.original, self.bytes)

    def patched(self):
        return map(lambda b: b.patched, self.bytes)


def PLUGIN_ENTRY():
    return patchgen()
