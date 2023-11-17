#!/usr/bin/env python3
# coding: UTF-8

# IDA libraries
import idaapi
import ida_kernwin
import ida_name
import idc

# Python modules
import os
import sys

class PatchManager(object):

    def __init__(self):
        self.patched_bytes = []
        self.prev_addr = None

    def generate(self):
        idaapi.visit_patched_bytes(0, idaapi.BADADDR, self.get_patch_byte)
        if len(self.patched_bytes) == 0:
            msg = 'Cannot generate patch because there is no patch applied.'
            print(f'genpatch: {msg}')
            ida_kernwin.warning(msg)
            return False

        template_path = ''
        for path in sys.path:
            if 'plugins' in path:
                template_path = os.path.join(path, 'patch_script_template.txt')

        patch_path = idc.get_input_file_path() + '_patch.py'

        template_data = None
        with open(template_path, 'r') as f:
            template_data = f.readlines()

        lines = 13
        with open(patch_path, 'w') as f:
            for data in self.patched_bytes:
                template_data.insert(lines, f"# address: 0x{data['begin_addr']:x}\n")
                lines += 1
                template_data.insert(lines, f"# function name: {data['func_name']}\n")
                lines += 1
                template_data.insert(lines, f"# comment: {data['comment']}\n")
                lines += 1
                template_data.insert(lines, f"matches = re.findall('{data['original']}', target_data)\n")
                lines += 1
                template_data.insert(lines, "if len(matches) == 1:\n")
                lines += 1
                template_data.insert(lines, f"    target_data = target_data.replace('{data['original']}', '{data['patched']}')\n")
                lines += 1
                template_data.insert(lines, "else:\n")
                lines += 1
                template_data.insert(lines, '    print("Patch pattern isn\'t unique")\n')
                lines += 1
                template_data.insert(lines, "    sys.exit()\n")
                lines += 1

            f.writelines(template_data)

        msg = f'Successfully generated patch to {patch_path} from Patched Bytes'
        print(f'genpatch: {msg}')
        ida_kernwin.info(msg)
        return True

    # callback in 3rd argument of idaapi.visit_patched_bytes
    def get_patch_byte(self, ea, fpos, org_val, patched_val):
        org_byte = f"{org_val:02x}"
        patched_byte = f"{patched_val:02x}"

        if self.prev_addr is None or ea != (self.prev_addr + 1):
            func_name = idc.get_segm_name(ea)
            if idc.get_func_name(ea) or idc.get_name(ea, ida_name.GN_VISIBLE):
                func_name += ': '
                func_name += idc.get_func_name(ea)
                func_name += idc.get_name(ea, ida_name.GN_VISIBLE)

            comment = idc.get_cmt(ea, 0) or idc.get_cmt(ea, 1) or ''
            comment = comment.replace('\n', ' ')

            self.patched_bytes.append({
                'func_name': func_name, 
                'begin_addr': ea, 
                'original': org_byte, 
                'patched': patched_byte, 
                'comment': comment
                })

        else:
            self.patched_bytes[-1]['original'] += org_byte
            self.patched_bytes[-1]['patched'] += patched_byte

        self.prev_addr = ea

        return 0


class genpatch_t(idaapi.plugin_t):

    flags = idaapi.PLUGIN_KEEP
    comment = 'generate patch from patched bytes'
    help = ''
    wanted_name = "genpatch"
    wanted_hotkey = ""

    def init(self):  
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        p = PatchManager()
        p.generate()

    def term(self):
        return None


def PLUGIN_ENTRY():
    return genpatch_t()
