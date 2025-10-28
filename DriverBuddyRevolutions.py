# DriverBuddyRevolutions.py
# Driver Buddy Revolutions
# Single-file IDA plugin implementing useful heuristics for Windows driver triage
#
# Place in IDA's plugins/ directory or run as script. Hotkey: Shift-A
#
# Date: 2025-10-24

import os
import re
import time
import json
import html
import tempfile
import traceback
import mmap
import collections
from math import ceil

import idaapi
import idc
import idautils
import ida_kernwin
import ida_funcs
import ida_bytes
import ida_nalt
import ida_name
import ida_xref
import ida_segment
import ida_search
import ida_lines
import ida_ua

# ---------------------------- Utility / filenames ----------------------------

def today(): return time.strftime("%Y-%m-%d")
def timestamp(): return time.strftime("%H%M%S")

DRIVER_NAME = idaapi.get_root_filename()
CWD = "{}{}".format(os.getcwd(), os.sep)
IOCTL_FILE = "{}-{}-{}-IOCTLs.txt".format(DRIVER_NAME, today(), timestamp())
POOL_FILE = "{}-{}-{}-PoolTags.txt".format(DRIVER_NAME, today(), timestamp())
ANALYSIS_FILE = "{}-{}-{}-DriverBuddyRevolutions_full_autoanalysis.txt".format(DRIVER_NAME, today(), timestamp())
HTML_REPORT_FILE = "{}-{}-{}-DriverBuddyRevolutions_report.html".format(DRIVER_NAME, today(), timestamp())
JSON_EXPORT_FILE = "{}-{}-{}-DriverBuddyRevolutions_findings.json".format(DRIVER_NAME, today(), timestamp())
POC_C_FILE = "{}-{}-{}-ioctl_pocs.c".format(DRIVER_NAME, today(), timestamp())

# ---------------------------- Config / lists ----------------------------

opcode_severity = {'rdpmc':'High', 'rdmsr':'High', 'wrmsr':'High'}

c_functions = [
    "strcpy","strcpyA","strcpyW","StrCpy","StrCpyA","StrCpyW","wcscpy","_ftcscpy","_mbccpy","_mbccpy_l",
    "_mbscpy","_tccpy","_tcscpy","lstrcpy","lstrcpyA","lstrcpyW","_fstrcpy","_ftccpy","ualstrcpyW",
    "StrCpyN","StrCpyNA","strcpynA","StrCpyNW","StrNCpy","strncpy","_strncpy_l","StrNCpyA","StrNCpyW",
    "lstrcpyn","lstrcpynA","lstrcpynW","wcsncpy","_wcsncpy_l","_mbsncpy","_mbsncpy_l","_mbsnbcpy","_mbsnbcpy_l",
    "_tcsncpy","_fstrncpy",
    "lstrcat","lstrcatA","lstrcatW","strcat","StrCat","strcatA","StrCatA","StrCatBuff","StrCatBuffA","StrCatBuffW",
    "strcatW","StrCatW","StrCatChainW","wcscat","_mbccat","_mbscat","_tccat","_tcscat","_ftcscat","_fstrcat","_ftccat",
    "lstrcatnA","lstrcatn","lstrcatnW","lstrncat","strncat","_strncat_l","StrCatN","StrCatNA","StrCatNW","StrNCat",
    "StrNCatA","StrNCatW","wcsncat","_wcsncat_l","_mbsncat","_mbsncat_l","_mbsnbcat","_mbsnbcat_l","_tcsncat","_fstrncat",
    "strtok","_strtok_l","wcstok","_wcstok_l","_mbstok","_mbstok_l","_tcstok",
    "makepath","_makepath","_splitpath","_tmakepath","_tsplitpath","_wmakepath","_wsplitpath",
    "_itoa","_i64toa","_i64tow","_itow","_ui64toa","_ui64tot","_ui64tow","_ultoa","_ultot","_ultow",
    "scanf","cscanf","_cscanf","_cscanf_l","_cwscanf","_cwscanf_l","_sntscanf","_stscanf","_tscanf","fscanf","_fscanf_l",
    "fwscanf","_fwscanf_l","snscanf","snwscanf","sscanf","_sscanf_l","swscanf","_swscanf_l","wscanf","vscanf","vwscanf",
    "vsscanf","vswscanf","vfscanf","vfwscanf","_snscanf","_snscanf_l","_snwscanf","_snwscanf_l",
    "_getts","_gettws","gets","_getws","cgets","_cgets","_cgetws",
    "strlen","_mbslen","_mbslen_l","_mbstrlen","_mbstrlen_l","lstrlen","StrLen","wcslen",
    "CopyMemory","RtlCopyMemory","memcpy","wmemcpy","memccpy","_memccpy",
    "_alloca","alloca","_malloca",
    "memmove","wmemmove","realloc","_realloc_dbg","_recalloc","_recalloc_dbg","_aligned_offset_realloc",
    "_aligned_offset_realloc_dbg","_aligned_offset_recalloc","_aligned_offset_recalloc_dbg","_aligned_realloc",
    "_aligned_realloc_dbg","_aligned_recalloc","_aligned_recalloc_dbg",
    "_snprintf","_snwprintf","_stprintf","_sntprintf","_swprintf","nsprintf","sprintf","sprintfA","sprintfW","swprintf",
    "std_strlprintf","wnsprintf","wnsprintfA","wnsprintfW","wsprintf","wsprintfA","wsprintfW","wvnsprintf","wvnsprintfA",
    "wvnsprintfW","wvsprintf","wvsprintfA","wvsprintfW","vsprintf","vsnprintf","vswprintf","_vsnprintf","_vsntprintf",
    "_vsnwprintf","_vstprintf",
    "fopen","_wfopen","fopen_s","_wfopen_s","freopen","_wfreopen","freopen_s","_wfreopen_s","_fsopen","_wfsopen",
    "open","_open","_wopen","sopen","_sopen","_wsopen","_sopen_s","_wsopen_s",
    "rewind","strlwr","wcslwr","_strlwr","_strlwr_l","_wcslwr","_wcslwr_l","_mbslwr","_mbslwr_l","strupr","wcsupr",
    "_strupr","_strupr_l","_wcsupr","_wcsupr_l","_mbsupr","_mbsupr_l","assert","_assert","_wassert","catgets",
    "getenv","_wgetenv","getenv_s","_wgetenv_s","_dupenv_s","_wdupenv_s","_dupenv_s_dbg","_wdupenv_s_dbg","_searchenv",
    "_wsearchenv","_searchenv_s","_wsearchenv_s","gethostbyname","setbuf","umask","_umask","_umask_s",
]

_c_functions_lc = set(fn.lower() for fn in c_functions)

winapi_prefixes = ['ProbeFor', 'Rtl', 'Ob', 'Zw', 'Mm', 'IofCallDriver', 'Io', 'Flt', 'ExAllocatePool']

HEURISTIC_LARGE_MAP_SIZE = 4 * 1024 * 1024  # 4MB

NTSTATUS_COMMON = {0x00000000, 0xC0000001, 0xC0000005, 0xC0000008, 0xC000000D, 0xC0000022}

VALIDATION_FUNCS = set(['ProbeForRead','ProbeForWrite','MmIsAddressValid','RtlULongAdd',
                        'RtlULongLongAdd','RtlULongSub','RtlULongLongMult','RtlSizeTAdd','RtlSizeTMult',
                        'RtlULongMult','try','__try','RtlCopyMemory_safe'])

IRQL_SENSITIVE_APIS = set(['KeRaiseIrql','KeLowerIrql','KeGetCurrentIrql','MmMapIoSpace','KeWaitForSingleObject'])

MDL_FUNCS = set(['MmProbeAndLockPages','MmMapLockedPagesSpecifyCache','IoBuildPartialMdl','MmGetSystemAddressForMdlSafe'])

SINKS = set(['memcpy','memmove','RtlCopyMemory','MmGetPhysicalAddress','MmMapIoSpace','MmMapIoSpaceEx'])

SENSITIVE_OPS = set(['ZwOpenSection','ZwMapViewOfSection','SeSinglePrivilegeCheck','SeAccessCheck','IoIsSystemThread'])

# ---------------------------- Helpers ----------------------------

def _lower_name_strip(callee):
    if not callee:
        return ''
    base = callee.split('@')[0].split('::')[-1]
    return base.lower()

def all_functions():
    for f in idautils.Functions():
        yield f, idc.get_func_name(f)

def get_sym_name(ea):
    try:
        return idc.get_name(ea, ida_name.GN_VISIBLE if hasattr(ida_name, 'GN_VISIBLE') else 0)
    except Exception:
        return idc.get_name(ea)

def decode_imm_operands(ea):
    outs = []
    insn = idaapi.insn_t()
    if idaapi.decode_insn(insn, ea) == 0:
        return outs
    for op in insn.ops:
        if op.type == idaapi.o_void:
            break
        if op.type == idaapi.o_imm:
            outs.append(op.value & 0xFFFFFFFF)
    return outs

def is_call(ea):
    try:
        return idaapi.print_insn_mnem(ea).lower() == 'call'
    except Exception:
        return False

def call_targets(ea):
    out = []
    if not is_call(ea):
        return out
    for xr in idautils.XrefsFrom(ea, ida_xref.XREF_FAR):
        nm = get_sym_name(xr.to)
        if nm:
            out.append(nm)
    return out

def func_items(func_ea):
    f = ida_funcs.get_func(func_ea)
    if not f:
        return []
    return list(idautils.FuncItems(f.start_ea))

def get_func_start(ea):
    f = ida_funcs.get_func(ea)
    if f:
        return f.start_ea
    return idaapi.BADADDR

# ---------------------------- IOCTL decode & scoring ----------------------------

def ioctl_decode_fields(code):
    v = int(code) & 0xFFFFFFFF
    device = (v >> 16) & 0xFFFF
    access = (v >> 14) & 0x3
    function = (v >> 2) & 0xFFF
    method = v & 0x3
    return {'raw':v, 'device':device, 'access':access, 'function':function, 'method':method}

def ioctl_fmt(code):
    d = ioctl_decode_fields(code)
    device_names = {0x0:'FILE_DEVICE_UNKNOWN',0x1:'FILE_DEVICE_BEEP',0x2:'FILE_DEVICE_CD_ROM',0x3:'FILE_DEVICE_CD_ROM_FILE_SYSTEM',
                    0x4:'FILE_DEVICE_CONTROLLER',0x5:'FILE_DEVICE_DATALINK',0x6:'FILE_DEVICE_DFS',0x7:'FILE_DEVICE_DISK',
                    0x8:'FILE_DEVICE_DISK_FILE_SYSTEM',0x9:'FILE_DEVICE_FILE_SYSTEM',0x12:'FILE_DEVICE_NETWORK',
                    0x13:'FILE_DEVICE_NETWORK_BROWSER',0x14:'FILE_DEVICE_NETWORK_FILE_SYSTEM',0x15:'FILE_DEVICE_NULL',
                    0x22:'FILE_DEVICE_UNKNOWN',0x23:'FILE_DEVICE_VIDEO'}
    device = device_names.get(d['device'], "0x%X" % d['device'])
    method_map = {0:'METHOD_BUFFERED',1:'METHOD_IN_DIRECT',2:'METHOD_OUT_DIRECT',3:'METHOD_NEITHER'}
    access_map = {0:'FILE_ANY_ACCESS',1:'FILE_READ_ACCESS',2:'FILE_WRITE_ACCESS',3:'FILE_READ_WRITE_ACCESS'}
    return "%s | func=%d method=%s access=%s" % (device, d['function'], method_map.get(d['method'],str(d['method'])),
                                                 access_map.get(d['access'],str(d['access'])))

def ioctl_risk_score(code):
    d = ioctl_decode_fields(code)
    score = 0
    reasons = []
    if d['method'] == 3:
        score += 40; reasons.append("METHOD_NEITHER (user pointers passed directly)")
    if d['access'] == 0:
        score += 20; reasons.append("FILE_ANY_ACCESS (no read/write required)")
    if d['device'] >= 0x200:
        score += 10; reasons.append("high/custom device code (3rd-party)")
    if d['function'] >= 0x800:
        score += 8;  reasons.append("large function number (heuristic)")
    if d['function'] == 0:
        score -= 5; reasons.append("function==0 (often benign)")

    if score >= 50:
        label = "Critical"
    elif score >= 30:
        label = "High"
    elif score >= 10:
        label = "Medium"
    else:
        label = "Low"
    return score, label, reasons

# ---------------------------- IOCTL discovery (disassembly heuristics) ----------------------------

def plausible_ioctl(v):
    try:
        vv = int(v) & 0xFFFFFFFF
    except Exception:
        return False
    method = vv & 3
    funcnum = (vv >> 2) & 0xFFF
    device = (vv >> 16) & 0xFFFF
    if method not in (0,1,2,3):
        return False
    if funcnum == 0 or device == 0:
        return False
    return True

def find_ioctls_in_func(func_ea):
    out = []
    f = ida_funcs.get_func(func_ea)
    if not f:
        return out
    try:
        fc = idaapi.FlowChart(f, flags=idaapi.FC_PREDS)
    except Exception:
        return out
    for block in fc:
        ea = block.start_ea
        while ea < block.end_ea:
            try:
                mnem = idc.print_insn_mnem(ea)
            except Exception:
                mnem = ''
            if mnem in ('cmp','sub','mov') and idc.get_operand_type(ea,1) == idaapi.o_imm:
                imm = idc.get_operand_value(ea,1) & 0xFFFFFFFF
                if imm >= 0x10000 and imm not in NTSTATUS_COMMON and plausible_ioctl(imm):
                    out.append((ea, imm))
            ea = idc.next_head(ea, block.end_ea)
    return out

def scan_all_ioctls():
    found = []
    handlers = set()
    for f_ea, fname in all_functions():
        hits = find_ioctls_in_func(f_ea)
        if hits:
            handlers.add(f_ea)
            found.extend(hits)
    seen = set(); dedup=[]
    for ea,code in found:
        if (ea,code) not in seen:
            seen.add((ea,code)); dedup.append((ea,code))
    return dedup, handlers

# ---------------------------- Pooltags ----------------------------

def find_pool_tags_via_imports():
    funcs = ["ExAllocatePoolWithTag","ExFreePoolWithTag","ExAllocatePool2","ExFreePool2","ExAllocatePool3",
             "ExAllocatePoolWithTagPriority","ExAllocatePoolWithQuotaTag","ExAllocatePoolZero","ExAllocatePoolQuotaZero",
             "ExAllocatePoolQuotaUninitialized","ExAllocatePoolPriorityZero","ExAllocatePoolPriorityUninitialized",
             "ExAllocatePoolUninitialized"]
    tags = {}
    def cb(ea, name, ord):
        if not name: return True
        if name in funcs:
            for xr in idautils.XrefsTo(ea):
                frm = xr.frm
                caller = idc.get_func_name(frm) or "<unknown>"
                prev = idc.prev_head(frm)
                for _ in range(10):
                    if prev == idaapi.BADADDR: break
                    try:
                        cmt = idc.get_cmt(prev,0) or ""
                    except Exception:
                        cmt = ""
                    if cmt == 'Tag' and idc.get_operand_type(prev,1) == idaapi.o_imm:
                        tag_raw = idc.get_operand_value(prev,1) & 0xFFFFFFFF
                        tag = ''.join(chr((tag_raw >> (8*i)) & 0xFF) for i in range(3,-1,-1))
                        tag = ''.join(ch if 32<=ord(ch)<=126 else '.' for ch in tag)
                        tags.setdefault(tag,set()).add(caller)
                        break
                    prev = idc.prev_head(prev)
        return True
    for i in range(idaapi.get_import_module_qty()):
        try:
            idaapi.enum_import_names(i, cb)
        except Exception:
            pass
    return tags

def collect_pooltags_fallback():
    tags={}
    allocs = ['ExAllocatePool','ExAllocatePoolWithTag','ExAllocatePool2','ExFreePoolWithTag']
    for f_ea,fname in all_functions():
        insns = func_items(f_ea)
        for idx,ea in enumerate(insns):
            if not is_call(ea): continue
            called = call_targets(ea)
            if not any(c.lower().startswith(a.lower()) for a in allocs for c in called): continue
            for prev_ea in insns[max(0,idx-8):idx]:
                for v in decode_imm_operands(prev_ea):
                    s = ''.join(chr((v>>(8*i))&0xFF) for i in range(4))
                    if all(32<=ord(ch)<=126 for ch in s):
                        alnum = sum(ch.isalnum() for ch in s)
                        if alnum >= 2:
                            tag = ''.join(ch if 32<=ord(ch)<=126 else '.' for ch in s)
                            tags.setdefault(tag,set()).add(fname)
    return tags

def get_all_pooltags():
    tags = find_pool_tags_via_imports()
    if not tags:
        tags = collect_pooltags_fallback()
    file_name = idaapi.get_root_filename()
    lines = []
    for tag in sorted(tags.keys()):
        callers = ", ".join(sorted(tags[tag]))
        lines.append("{} - {} - Called by: {}".format(tag, file_name, callers))
    return tags, "\n".join(lines)

# ---------------------------- Device names ----------------------------

ASCII_BYTE = b" !\"#\\$%&'\\(\\)\\*\\+,-\\./0123456789:;<=>\\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\\[\\]\\^_`abcdefghijklmnopqrstuvwxyz\\{\\|\\}\\\\~\t"
UNICODE_RE_4 = re.compile(b"((?:[%s]\x00){4,})" % ASCII_BYTE)
REPEATS = [b"A", b"\x00", b"\xfe", b"\xff"]
SLICE_SIZE = 4096
StringMatch = collections.namedtuple("StringMatch", ["s","offset"])

def _buf_filled_with(buf, first_b):
    dupe = first_b * SLICE_SIZE
    for off in range(0, len(buf), SLICE_SIZE):
        chunk = buf[off:off+SLICE_SIZE]
        if dupe[:len(chunk)] != chunk:
            return False
    return True

def _extract_unicode_strings(buf, n=4):
    if not buf: return
    first_b = bytes([buf[0]])
    if any(first_b == r for r in REPEATS) and _buf_filled_with(buf, first_b):
        return
    r = UNICODE_RE_4 if n==4 else re.compile(b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, n))
    for m in r.finditer(buf):
        try:
            yield StringMatch(m.group().decode("utf-16"), m.start())
        except UnicodeDecodeError:
            pass

def _get_input_path():
    p = ida_nalt.get_input_file_path()
    if p and os.path.exists(p): return p
    r = ida_nalt.get_root_filename()
    dbdir = os.path.dirname(idaapi.get_path(idaapi.PATH_TYPE_IDB))
    cand = os.path.join(dbdir, r)
    if os.path.exists(cand): return cand
    return None

def unicode_device_candidates():
    p = _get_input_path()
    out = set()
    if not p: return out
    try:
        with open(p,'rb') as f:
            mm = mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
            for s in _extract_unicode_strings(mm, n=4):
                sval = str(s.s)
                low = sval.lower()
                if low.startswith("\\device\\") or low.startswith("\\dosdevices\\") or low.startswith("\\??\\"):
                    out.add(sval)
            mm.close()
    except Exception:
        pass
    return out

def ida_string_device_candidates():
    out = set()
    try:
        s = idautils.Strings(); s.setup()
    except Exception:
        return out
    for st in s:
        try:
            sval = str(st)
        except Exception:
            continue
        low = sval.lower()
        if "\\device\\" in low or "\\dosdevices\\" in low or "\\??\\" in low:
            out.add(sval)
    return out

def find_device_names_lines():
    uni = unicode_device_candidates()
    ascii = ida_string_device_candidates()
    combo = set(); combo.update(uni); combo.update(ascii)
    lines = []
    if not combo:
        lines.append("[!] No potential DeviceNames found; try FLOSS for stack-built strings.")
        return lines
    for nm in sorted(combo):
        if nm.strip().lower() in ("\\device\\","\\dosdevices\\","\\??\\"): continue
        lines.append("  - {}".format(nm.strip()))
    if not lines:
        lines.append("[!] Device prefix found but no full path; may be built on stack.")
    return lines

# ---------------------------- DriverEntry & dispatch heuristics ----------------------------

def is_driver_exported():
    exps = set(x[3] for x in idautils.Entries())
    return 'DriverEntry' in exps

def find_driver_entry():
    ea = idc.get_name_ea_simple("DriverEntry")
    if ea != idaapi.BADADDR:
        return ea
    for f_ea, fname in all_functions():
        if fname and fname.lower().endswith("driverentry"):
            return f_ea
    return None

def find_real_driver_entry(driver_entry_ea):
    lines=[]
    if driver_entry_ea is None: return driver_entry_ea, lines
    f = idaapi.get_func(driver_entry_ea)
    if not f: return driver_entry_ea, lines
    cur = f.end_ea
    while cur>=f.start_ea:
        m = idc.print_insn_mnem(cur)
        if m in ('jmp','call'): break
        cur -= 1
    if cur < f.start_ea:
        lines.append("[!] Could not find tail jump/call for DriverEntry")
        return driver_entry_ea, lines
    tgt = idc.print_operand(cur,0)
    try:
        real = idc.get_name_ea_simple(tgt)
    except Exception:
        real = idaapi.BADADDR
    if real not in (idaapi.BADADDR, None):
        if real != driver_entry_ea:
            idc.set_name(real, "Real_Driver_Entry", idc.SN_AUTO)
            lines.append("[+] Found REAL DriverEntry at 0x%08X" % real)
            return real, lines
    lines.append("[!] Using DriverEntry at 0x%08X" % driver_entry_ea)
    return driver_entry_ea, lines

def locate_ddc_via_driverobj(real_driver_entry_ea):
    dispatch = {}
    lines = []
    if real_driver_entry_ea is None: return dispatch, lines
    insns = list(idautils.FuncItems(real_driver_entry_ea))
    prev = insns[0] if insns else None
    ddc_offset = "+0E0h]"
    didc_offset = "+0E8h]"
    for i in insns[1:]:
        op0 = idc.print_operand(i,0)
        if prev and idc.print_insn_mnem(prev) == 'lea':
            if ddc_offset in op0:
                tgt = idc.get_name_ea_simple(idc.print_operand(prev,1))
                if tgt != idaapi.BADADDR:
                    dispatch['ddc'] = tgt; idc.set_name(tgt,"DispatchDeviceControl", idc.SN_AUTO)
                    lines.append("[+] Found DispatchDeviceControl at 0x%08X"%tgt)
            if didc_offset in op0:
                tgt = idc.get_name_ea_simple(idc.print_operand(prev,1))
                if tgt != idaapi.BADADDR:
                    dispatch['didc']=tgt; idc.set_name(tgt,"DispatchInternalDeviceControl", idc.SN_AUTO)
                    lines.append("[+] Found DispatchInternalDeviceControl at 0x%08X"%tgt)
        prev = i
    return dispatch, lines

def find_dispatch_candidates_by_cfg():
    called = set(); caller_counts={}
    for f_ea in idautils.Functions():
        flags = idc.get_func_flags(f_ea)
        if flags & idaapi.FUNC_LIB: continue
        fname = idc.get_func_name(f_ea)
        for ref in idautils.CodeRefsTo(f_ea,0):
            called.add(fname)
            caller = idc.get_func_name(ref)
            caller_counts[caller] = caller_counts.get(caller,0)+1
    out = []
    while caller_counts:
        cand = max(caller_counts, key=caller_counts.get)
        if cand not in called:
            out.append(cand)
        del caller_counts[cand]
    return out

def find_dispatch_candidates_combined():
    lines=[]
    idx_funcs=set()
    for f_ea in idautils.Functions():
        flags = idc.get_func_flags(f_ea)
        if flags & idaapi.FUNC_LIB: continue
        func = idaapi.get_func(f_ea)
        if not func: continue
        ea=func.start_ea
        while ea < func.end_ea:
            if idc.print_insn_mnem(ea) == 'mov':
                op0 = idc.print_operand(ea,0)
                if '+70h' in op0 and idc.get_operand_type(ea,1) == idaapi.o_imm:
                    idx_funcs.add(idc.print_operand(ea,1))
            ea = idc.next_head(ea, func.end_ea)
    cfg = find_dispatch_candidates_by_cfg()
    if not idx_funcs:
        lines.append("[>] Based off CFG, potential dispatch functions:")
        for i in cfg[:3]: lines.append("  - %s"%i)
    elif len(idx_funcs) == 1:
        candidate = next(iter(idx_funcs))
        if candidate in cfg:
            lines.append("[>] Likely dispatch: %s"%candidate)
        else:
            lines.append("[>] Candidate via struct offset: %s"%candidate)
            if cfg:
                lines.append("[>] CFG guess: %s"%cfg[0])
    else:
        lines.append("[>] Potential dispatch functions (struct offset):")
        for i in idx_funcs:
            if i in cfg: lines.append("  - %s"%i)
    return lines

# ---------------------------- Heuristics: probe/validation & IRQL ----------------------------

def has_nearby_validation(func_ea, insn_ea, lookback=20, lookforward=6):
    insns = func_items(func_ea)
    if insn_ea not in insns:
        return False
    idx = insns.index(insn_ea)
    start = max(0, idx - lookback)
    end = min(len(insns), idx + lookforward)
    for ea in insns[start:end]:
        if is_call(ea):
            for tgt in call_targets(ea):
                base = _lower_name_strip(tgt)
                for v in VALIDATION_FUNCS:
                    if base == v.lower() or v.lower() in base:
                        return True
        try:
            c = idc.get_cmt(ea,0) or ""
        except Exception:
            c = ""
        if any(v.lower() in c.lower() for v in VALIDATION_FUNCS):
            return True
    return False

def detect_irql_misuse_in_func(func_ea):
    issues=[]
    insns = func_items(func_ea)
    seen_irql_check=False
    for ea in insns:
        if is_call(ea):
            for tgt in call_targets(ea):
                low=_lower_name_strip(tgt)
                if low == 'kegetcurrentirql':
                    seen_irql_check=True
                if low in (name.lower() for name in IRQL_SENSITIVE_APIS) and seen_irql_check:
                    issues.append("IRQL-sensitive API '%s' used near KeGetCurrentIrql at 0x%X" % (tgt, ea))
                if low.startswith('zw') or low.startswith('mmmap') or low.startswith('mmget'):
                    issues.append("Potential IRQL misuse: %s at 0x%X" % (tgt, ea))
    return issues

# ---------------------------- Taint propagation (simple) ----------------------------

def taint_from_ioctl_dispatch(ioctl_handlers, sinks=SINKS, max_depth=5):
    results = {}
    cg = {}
    for f_ea, fname in all_functions():
        callees=set()
        for ea in func_items(f_ea):
            if is_call(ea):
                for t in call_targets(ea):
                    callees.add(t)
        cg[fname] = callees

    for handler in ioctl_handlers:
        hname = idc.get_func_name(handler) or "sub_%X" % handler
        queue = [(hname, [hname], 0)]
        visited=set([hname])
        while queue:
            cur, path, depth = queue.pop(0)
            for callee in cg.get(cur, []):
                base = callee.split('@')[0].split('::')[-1]
                if base.lower() in (s.lower() for s in sinks):
                    results.setdefault(callee, []).append(path + [callee])
                if depth < max_depth and callee not in visited:
                    visited.add(callee)
                    queue.append((callee, path+[callee], depth+1))
    return results

# ---------------------------- Exported API audit ----------------------------

def exported_api_audit():
    exports = list(idautils.Entries())
    exps = [e[3] for e in exports]
    reachable = []
    for e in exports:
        name = e[3]
        addr = e[0]
        refs = list(idautils.CodeRefsTo(addr, 0))
        if refs:
            reachable.append((name, addr, len(refs)))
    return exps, reachable

# ---------------------------- Stack/heap allocation heuristics ----------------------------

def detect_alloca_and_large_stack():
    results=[]
    for f_ea, fname in all_functions():
        f = ida_funcs.get_func(f_ea)
        if not f: continue
        insns=func_items(f_ea)
        for ea in insns:
            if is_call(ea):
                for tgt in call_targets(ea):
                    if _lower_name_strip(tgt) in ('_alloca','alloca','_malloca'):
                        results.append((fname, ea, tgt))
    return results

def detect_suspicious_allocs(func_ea):
    return []

# ---------------------------- IRP/MDL misuse patterns ----------------------------

def detect_mdl_irp_misuse():
    issues=[]
    for f_ea, fname in all_functions():
        insns = func_items(f_ea)
        for ea in insns:
            if is_call(ea):
                for tgt in call_targets(ea):
                    base=_lower_name_strip(tgt)
                    if any(base.startswith(m.lower()) for m in MDL_FUNCS):
                        snippet = idc.GetDisasm(ea)
                        s = idc.get_cmt(ea,0) or ''
                        usermode = 'UserMode' in snippet or 'UserMode' in s or ', 1,' in snippet
                        sev = "High" if usermode else "Medium"
                        issues.append((sev, fname, ea, tgt, usermode))
    return issues

# ---------------------------- Interesting calls / opcode scanning ----------------------------

def build_interesting_call_lists():
    opcode_hits=[]; c_hits=[]; api_hits=[]
    for f_ea, fname in all_functions():
        for ea in func_items(f_ea):
            try:
                mnem = idaapi.print_insn_mnem(ea).lower()
            except Exception:
                mnem = ''
            if mnem in opcode_severity:
                opcode_hits.append((mnem, fname, ea))
            if is_call(ea):
                for tgt in call_targets(ea):
                    if call_is_c_function(tgt):
                        c_hits.append((tgt, fname, ea))
                    for pref in winapi_prefixes:
                        if tgt.startswith(pref):
                            api_hits.append((tgt,fname,ea))
    return opcode_hits, c_hits, api_hits

def call_is_c_function(callee_name):
    if not callee_name: return False
    base = callee_name.split('@')[0].split('::')[-1]
    return base.lower() in _c_functions_lc

# ---------------------------- POC / Fuzzer generator ----------------------------
# FIXED: use .format() for both header & body, escape { } and % so Python doesn't treat them as placeholders.

def generate_ioctl_poc_c(ioctls, outpath=POC_C_FILE, device_path="\\\\.\\PUT_DEVICE_NAME_HERE"):
    """
    Generates simple C program that calls DeviceIoControl for each IOCTL.
    Analyst must replace device_path string with real device.
    """

    header = (
        "#include <windows.h>\n"
        "#include <stdio.h>\n"
        "#include <stdint.h>\n"
        "\n"
        "int main(void){{\n"
        "    HANDLE h = CreateFileA(\"{dev}\", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);\n"
        "    if(h == INVALID_HANDLE_VALUE){{ printf(\"Open failed: %%u\\n\", GetLastError()); return 1; }}\n"
        "\n"
    ).format(dev=device_path)

    # For each ioctl:
    # - Escape braces in C blocks: {{ }}
    # - Escape % in printf with %% so .format() doesn't think it's Python formatting
    pieces = []
    for ea, code in ioctls:
        pieces.append(
            "    {{ // IOCTL 0x{code:08X}\n"
            "        DWORD bytes = 0;\n"
            "        uint8_t inbuf[512] = {{0}};\n"
            "        uint8_t outbuf[512] = {{0}};\n"
            "        BOOL ok = DeviceIoControl(h, 0x{code:08X}, inbuf, sizeof(inbuf), outbuf, sizeof(outbuf), &bytes, NULL);\n"
            "        printf(\"IOCTL 0x{code:08X} -> %s\\n\", ok? \"OK\":\"FAILED\");\n"
            "    }}\n\n"
            .format(code=code)
        )

    body = "".join(pieces)

    footer = (
        "    CloseHandle(h);\n"
        "    return 0;\n"
        "}\n"
    )

    try:
        with open(outpath, "w") as f:
            f.write(header + body + footer)
        return outpath
    except Exception as e:
        ida_kernwin.msg("[!] Failed to write POC C file: %s\n" % str(e))
        return None

# ---------------------------- HTML report generator (simple clickable) ----------------------------

def make_html_report(findings, outpath=HTML_REPORT_FILE):
    def ea_link(ea):
        return '<a href="#" onclick="window.location.href=\'ida://jump?ea=%s\'">0x%X</a>' % (hex(ea), ea)
    html_parts=[]
    html_parts.append("<html><head><meta charset='utf-8'><title>Driver Buddy Revs Report</title></head><body>")
    html_parts.append("<h1>Driver Buddy Revs - Findings for %s</h1>"%html.escape(DRIVER_NAME))
    html_parts.append("<h2>Summary</h2>")
    html_parts.append("<ul>")
    for k,v in findings.get('summary',{}).items():
        html_parts.append("<li><b>%s</b>: %s</li>"%(html.escape(k), html.escape(str(v))))
    html_parts.append("</ul>")

    html_parts.append("<h2>IOCTLs</h2><table border=1 cellpadding=4><tr><th>EA</th><th>Code</th><th>Score</th><th>Reasons</th></tr>")
    for ea, code, score,label,reasons in findings.get('ioctls',[]):
        html_parts.append("<tr>")
        html_parts.append("<td>%s</td>"%ea_link(ea))
        html_parts.append("<td>0x%08X</td>"%code)
        html_parts.append("<td>%s (%d)</td>"%(label, score))
        html_parts.append("<td>%s</td>"%html.escape(", ".join(reasons)))
        html_parts.append("</tr>")
    html_parts.append("</table>")

    html_parts.append("<h2>Pooltags</h2><pre>%s</pre>"%html.escape(findings.get('pooltags_text',"(none)")))
    html_parts.append("<h2>Device Names</h2><pre>%s</pre>"%html.escape("\n".join(findings.get('devicenames',[]))))

    html_parts.append("<h2>Taint paths (IOCTL -> sink)</h2>")
    for sink, paths in findings.get('taint_paths',{}).items():
        html_parts.append("<h3>%s</h3><ul>"%html.escape(sink))
        for p in paths:
            seq = " &rarr; ".join(["%s" % html.escape(x) for x in p])
            html_parts.append("<li>%s</li>"%seq)
        html_parts.append("</ul>")

    html_parts.append("<h2>Heuristic Findings</h2><ul>")
    for item in findings.get('heuristics',[]):
        ea = item.get('ea', None)
        title = item.get('title','')
        details = item.get('details','')
        if ea:
            link = ea_link(ea)
            html_parts.append("<li>%s at %s: %s</li>"%(html.escape(title), link, html.escape(details)))
        else:
            html_parts.append("<li>%s: %s</li>"%(html.escape(title), html.escape(details)))
    html_parts.append("</ul>")

    html_parts.append("</body></html>")
    try:
        with open(outpath,"w",encoding="utf-8") as f:
            f.write("\n".join(html_parts))
        return outpath
    except Exception:
        return None

# ---------------------------- Main analysis orchestration ----------------------------

def run_full_analysis():
    start=time.time()
    results = {}
    try:
        ida_kernwin.msg("[*] Driver Buddy Revs - starting full analysis...\n")
        idc.auto_wait()

        findings_lines = []
        findings_lines.append("[#] Driver Buddy Revolutions - Full analysis")
        findings_lines.append("-----------------------------------------------")

        file_type = idaapi.get_file_type_name()
        if "portable executable" not in file_type.lower():
            findings_lines.append("[!] Not a PE - aborting")
            ida_kernwin.msg("[!] Not a PE file\n")
            return

        exported = is_driver_exported()
        if not exported:
            findings_lines.append("[!] WARN: DriverEntry not exported; may not be a driver")
        de = find_driver_entry()
        if de:
            findings_lines.append("[+] DriverEntry located at 0x%08X" % de)
            real_de, real_lines = find_real_driver_entry(de)
            findings_lines.extend(real_lines)
        else:
            findings_lines.append("[!] DriverEntry not found")

        import_names = set()
        def cb(ea,name,ord): 
            if name: import_names.add(name)
            return True
        for i in range(idaapi.get_import_module_qty()):
            try:
                idaapi.enum_import_names(i, cb)
            except Exception:
                pass
        driver_type = "WDM"
        if "FltRegisterFilter" in import_names: driver_type = "Mini-Filter"
        elif "WdfVersionBind" in import_names: driver_type = "WDF"
        elif "StreamClassRegisterMinidriver" in import_names: driver_type = "Stream Minidriver"
        elif "KsCreateFilterFactory" in import_names: driver_type = "AVStream"
        elif "PcRegisterSubdevice" in import_names: driver_type = "PortCls"
        findings_lines.append("[+] Driver type detected: %s" % driver_type)

        findings_lines.append("[>] Searching for DeviceNames...")
        devlines = find_device_names_lines()
        for l in devlines: findings_lines.append(l)

        findings_lines.append("[>] Searching for Pooltags...")
        tags, pool_text = get_all_pooltags()
        if pool_text:
            for l in pool_text.splitlines():
                findings_lines.append("  - "+l)
        else:
            findings_lines.append("  - (none detected)")

        findings_lines.append("[>] Searching for IOCTLs via disassembly heuristics...")
        ioctls, ioctl_handlers = scan_all_ioctls()
        ioctls_scored=[]
        for ea,code in ioctls:
            score,label,reasons = ioctl_risk_score(code)
            ioctls_scored.append((ea,code,score,label,reasons))
            findings_lines.append("  - 0x%08X : 0x%08X -> %s [%s]" % (ea, code, ioctl_fmt(code), label))
        results['ioctls'] = ioctls_scored

        try:
            with open(os.path.join(CWD, IOCTL_FILE),'w') as f:
                for ea,code,score,label,reasons in ioctls_scored:
                    f.write("0x%08X : 0x%08X | %s | %s (%d) | %s\n" % (ea, code, ioctl_fmt(code), label, score, ", ".join(reasons)))
            findings_lines.append("[>] Saved IOCTLs to %s" % IOCTL_FILE)
        except Exception:
            pass

        opcode_hits, c_hits, api_hits = build_interesting_call_lists()
        findings_lines.append("[>] Scanning for interesting C/C++ functions and opcodes...")
        if c_hits:
            for tgt, fn, ea in sorted(c_hits, key=lambda x:(x[0].lower(), x[1], x[2])):
                findings_lines.append("  - Found %s in %s at 0x%X" % (tgt, fn, ea))
        else:
            findings_lines.append("  - (none detected)")

        findings_lines.append("[>] Sensitive heuristics and MDL/IRP checks...")
        sens_lines=[]
        try:
            s_iter = idautils.Strings(); s_iter.setup()
            for s in s_iter:
                try:
                    if str(s) == "\\Device\\PhysicalMemory":
                        for xr in idautils.XrefsTo(s.ea):
                            func_ea = get_func_start(xr.frm)
                            fname = idc.get_func_name(func_ea) or "<no func>"
                            sev = "High" if func_ea in ioctl_handlers else "Medium"
                            sens_lines.append({"title":"PhysicalMemory reference","ea":xr.frm,"details":"%s in %s" % (hex(xr.frm), fname),"severity":sev})
                except Exception:
                    pass
        except Exception:
            pass

        mdl_issues = detect_mdl_irp_misuse()
        for sev, fname, ea, tgt, usermap in mdl_issues:
            sens_lines.append({"title":"MDL/IRP usage","ea":ea,"details":"%s in %s (usermap=%s)"%(tgt,fname,str(usermap)),"severity":sev})

        for f_ea, fname in all_functions():
            irql_issues = detect_irql_misuse_in_func(f_ea)
            for it in irql_issues:
                sens_lines.append({"title":"IRQL heuristic","ea":f_ea,"details":it,"severity":"Medium"})

        results['sensitive'] = sens_lines

        findings_lines.append("[>] Scanning for general vulnerabile patterns (user-copy, allocs, privilege gating)...")
        heuristics=[]
        for f_ea, fname in all_functions():
            insns = func_items(f_ea)
            in_ioctl_ctx = (f_ea in ioctl_handlers)
            for ea in insns:
                if is_call(ea):
                    for tgt in call_targets(ea):
                        base = _lower_name_strip(tgt)
                        if base in ('memcpy','memmove','rtlcopymemory'):
                            has_val = has_nearby_validation(f_ea, ea, lookback=20, lookforward=6)
                            if (not has_val) and in_ioctl_ctx:
                                heuristics.append({"title":"User copy without validation","ea":ea,"details":"%s in %s (no nearby validation)"%(tgt,fname),"severity":"High"})
                            elif not has_val:
                                heuristics.append({"title":"User copy without validation (non-ioctl)","ea":ea,"details":"%s in %s"%(tgt,fname),"severity":"Medium"})
                        if base.startswith('exallocatepool'):
                            has_val = has_nearby_validation(f_ea, ea, lookback=20, lookforward=6)
                            if (not has_val) and in_ioctl_ctx:
                                heuristics.append({"title":"Potential integer overflow in allocation","ea":ea,"details":"%s in %s (no safe arithmetic checks)"%(tgt,fname),"severity":"High"})
                        if base in (x.lower() for x in SENSITIVE_OPS):
                            has_guard = any(_lower_name_strip(c).startswith('sesingleprivilegecheck') or _lower_name_strip(c).startswith('seaccesscheck') for c in sum((call_targets(x) for x in insns if is_call(x)), []))
                            if in_ioctl_ctx and not has_guard:
                                heuristics.append({"title":"Missing privilege gate","ea":f_ea,"details":"sensitive op %s used without guard in IOCTL context"%tgt,"severity":"High"})
        results['heuristics'] = heuristics

        findings_lines.append("[>] Running best-effort taint propagation from IOCTL handlers...")
        taint_paths = taint_from_ioctl_dispatch(ioctl_handlers, sinks=SINKS, max_depth=6)
        results['taint_paths'] = taint_paths

        findings_lines.append("[>] Auditing exports and reachability...")
        exps, reachable = exported_api_audit()
        results['exports'] = {"all": exps, "reachable": reachable}

        findings_lines.append("[>] Finding alloca/stack/heap heuristics...")
        alloca = detect_alloca_and_large_stack()
        results['alloca']=alloca

        findings = {
            "summary": {
                "driver_name": DRIVER_NAME,
                "driver_type": driver_type,
                "driver_entry": ("0x%08X"%de) if de else None,
                "ioctl_count": len(ioctls_scored),
                "pooltags_count": len(tags),
            },
            "ioctls": ioctls_scored,
            "pooltags_text": pool_text,
            "devicenames": devlines,
            "sensitive": sens_lines,
            "heuristics": heuristics,
            "taint_paths": taint_paths,
            "exports": results['exports'],
            "alloca": alloca,
        }
        results.update(findings)

        try:
            with open(os.path.join(CWD, JSON_EXPORT_FILE),'w',encoding='utf-8') as jf:
                json.dump(results, jf, indent=2, default=str)
            findings_lines.append("[>] Saved JSON findings to %s" % JSON_EXPORT_FILE)
        except Exception:
            pass

        htmlpath = os.path.join(CWD, HTML_REPORT_FILE)
        if make_html_report(results, htmlpath):
            findings_lines.append("[>] Saved HTML report to %s" % HTML_REPORT_FILE)

        pocpath = generate_ioctl_poc_c([(ea,code) for ea,code,_,_,_ in ioctls_scored], outpath=os.path.join(CWD, POC_C_FILE))
        if pocpath:
            findings_lines.append("[>] Wrote C POC stubs to %s (edit device path and compile)" % POC_C_FILE)

        try:
            if pool_text:
                with open(os.path.join(CWD, POOL_FILE),'w') as pf:
                    pf.write(pool_text)
                findings_lines.append("[>] Saved Pooltags to %s" % POOL_FILE)
        except Exception:
            pass

        try:
            with open(os.path.join(CWD, ANALYSIS_FILE),'w') as af:
                for l in findings_lines:
                    af.write(l + "\n")
            findings_lines.append("[>] Saved analysis log to %s" % ANALYSIS_FILE)
        except Exception:
            pass

        chooser_items = []
        for h in heuristics:
            sev = h.get('severity','Medium')
            title = h.get('title','')
            ea = h.get('ea', None) or 0
            details = h.get('details','')
            chooser_items.append((sev, title, "0x%X" % ea, details))
        if chooser_items:
            class FindingsChoose(ida_kernwin.Choose):
                def __init__(self, title, items):
                    ida_kernwin.Choose.__init__(self, title, [["Severity",8],["Finding",40],["EA",18],["Details",60]], width=800)
                    self.items = items
                def OnGetSize(self): return len(self.items)
                def OnGetLine(self, n): return [self.items[n][0], self.items[n][1], self.items[n][2], self.items[n][3]]
                def OnSelectLine(self, n): 
                    try:
                        ea = int(self.items[n][2],16); ida_kernwin.jumpto(ea)
                    except Exception: pass
            c = FindingsChoose("Driver Buddy Findings", chooser_items)
            c.Show(True)

        ida_kernwin.msg("\n".join(findings_lines) + "\n")
        ida_kernwin.msg("[i] Driver Buddy full analysis completed in %.2f seconds\n" % (time.time() - start))

    except Exception as e:
        ida_kernwin.msg("[!] Driver Buddy crashed: %s\n" % traceback.format_exc())

# ---------------------------- plugin boilerplate ----------------------------

class driver_buddy_revolutions_full_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Driver Buddy Revolutions - full feature set (no Hex-Rays)"
    help = "Run Shift-A to start"
    wanted_name = "Driver Buddy Revolutions (full)"
    wanted_hotkey = "Shift-A"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        run_full_analysis()

    def term(self):
        pass

def PLUGIN_ENTRY():
    return driver_buddy_revolutions_full_t()
