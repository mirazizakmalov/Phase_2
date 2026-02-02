import sys
import os
import re

MEM_RE = re.compile(r"""
^
(?P<off>-?(?:0x[0-9a-fA-F]+|\d+))   # offset: hex or decimal, optional minus
\s*
\(
\s*
(?P<base>[a-zA-Z0-9_]+)            # base register token
\s*
\)
$
""", re.VERBOSE)

SYMPART_RE = re.compile(r"^%(?P<part>hi|lo)\s*\(\s*(?P<sym>[a-zA-Z_]\w*)\s*\)$")
IMM_RE     = re.compile(r"^-?(?:0x[0-9a-fA-F]+|\d+)$")
SYM_RE     = re.compile(r"^[a-zA-Z_]\w*$")


# Data Type Sizes
DATA_TYPES = {
    ".byte": {"size": 1,}, 
    ".half": {"size": 2,},
    ".word": {"size": 4,}, 
    ".dword": {"size": 8,}, 
    ".float": {"size": 4,},
    ".double": {"size": 8,},
    ".space": {"size": None,}, 
    ".ascii": {"size": None,},
    ".asciz": {"size": None,} 
}

DATA_BASE = 0x00000000

TEXT_BASE = 0x00000000


R_TYPE = {
    "add":  {"opcode": 0x33, "funct3": 0x0, "funct7": 0x00},
    "sub":  {"opcode": 0x33, "funct3": 0x0, "funct7": 0x20},
    "sll":  {"opcode": 0x33, "funct3": 0x1, "funct7": 0x00},
    "slt":  {"opcode": 0x33, "funct3": 0x2, "funct7": 0x00},
    "sltu": {"opcode": 0x33, "funct3": 0x3, "funct7": 0x00},
    "xor":  {"opcode": 0x33, "funct3": 0x4, "funct7": 0x00},
    "srl":  {"opcode": 0x33, "funct3": 0x5, "funct7": 0x00},
    "sra":  {"opcode": 0x33, "funct3": 0x5, "funct7": 0x20},
    "or":   {"opcode": 0x33, "funct3": 0x6, "funct7": 0x00},
    "and":  {"opcode": 0x33, "funct3": 0x7, "funct7": 0x00},
}


I_TYPE_ALU = {
    "addi":  {"opcode": 0x13, "funct3": 0x0},
    "slti":  {"opcode": 0x13, "funct3": 0x2},
    "sltiu": {"opcode": 0x13, "funct3": 0x3},
    "xori":  {"opcode": 0x13, "funct3": 0x4},
    "ori":   {"opcode": 0x13, "funct3": 0x6},
    "andi":  {"opcode": 0x13, "funct3": 0x7},
}


I_TYPE_SHIFT = {
    "slli": {"opcode": 0x13, "funct3": 0x1, "funct7": 0x00},
    "srli": {"opcode": 0x13, "funct3": 0x5, "funct7": 0x00},
    "srai": {"opcode": 0x13, "funct3": 0x5, "funct7": 0x20},
}


I_TYPE_LOAD = {
    "lb":  {"opcode": 0x03, "funct3": 0x0},
    "lh":  {"opcode": 0x03, "funct3": 0x1},
    "lw":  {"opcode": 0x03, "funct3": 0x2},
    "lbu": {"opcode": 0x03, "funct3": 0x4},
    "lhu": {"opcode": 0x03, "funct3": 0x5},
}


S_TYPE_STORE = {
    "sb": {"opcode": 0x23, "funct3": 0x0},
    "sh": {"opcode": 0x23, "funct3": 0x1},
    "sw": {"opcode": 0x23, "funct3": 0x2},
}


B_TYPE_BRANCH = {
    "beq":  {"opcode": 0x63, "funct3": 0x0},
    "bne":  {"opcode": 0x63, "funct3": 0x1},
    "blt":  {"opcode": 0x63, "funct3": 0x4},
    "bge":  {"opcode": 0x63, "funct3": 0x5},
    "bltu": {"opcode": 0x63, "funct3": 0x6},
    "bgeu": {"opcode": 0x63, "funct3": 0x7},
}

U_TYPE = {
    "lui":   {"opcode": 0x37},
    "auipc": {"opcode": 0x17},
}


J_TYPE = {
    "jal": {"opcode": 0x6F},
}

I_TYPE_JALR = {
    "jalr": {"opcode": 0x67, "funct3": 0x0},
}

I_TYPE_SYSTEM = {
    "ecall":  {"opcode": 0x73, "funct3": 0x0, "imm12": 0x000},
    "ebreak": {"opcode": 0x73, "funct3": 0x0, "imm12": 0x001},
    }

def initialScan(lines):
    #First pass: scan .data to compute data bytes and addresses, then scan .text to record label addresses

    labels = {}
    text_address = 0x00000000
    data_address = DATA_BASE
    i = 0
    in_data = False
    in_text = False
    entry_label = None

    # single pass scanning that handles both sections
    while i < len(lines):
        line = lines[i].strip()

        # skip blanks and comments
        if not line or line.startswith('#'):
            i += 1
            continue

        # section switches
        if line.startswith('.data'):
            in_data = True
            in_text = False
            i += 1
            continue
        
        m_glob = re.match(r'^\.(?:global|globl)\b(?:\s+(?P<label>[A-Za-z_]\w*))?', line)
        if line.startswith('.text') or m_glob:
            in_text = True
            in_data = False
            if m_glob and m_glob.group('label') and entry_label is None:
                entry_label = m_glob.group('label')
            i += 1
            continue

        if in_data:
            # If label on its own line: record its current data address
            if ':' in line:
                label_name = line.split(':', 1)[0].strip()
                labels[label_name] = data_address
                
                rest = line.split(':', 1)[1].strip()
                if not rest:
                    i += 1
                    continue
                
                line = rest

            # ASCII handling
            if '.ascii' in line or '.asciz' in line or '.asciiz' in line:
                match = re.search(r'"([^"]*)"', line)
                if match:
                    s = match.group(1)
                    data_address += len(s.encode('utf-8'))
                    # null-terminated variant
                    if '.asciz' in line or '.asciiz' in line:
                        data_address += 1
            # Handle .space separately
            elif '.space' in line:
                parts = line.split()
                if len(parts) >= 2:
                    size = int(parts[1])
                    data_address += size
            else:
                # Handle numeric directives like .byte, .half, .word, .dword
                for struct, data in DATA_TYPES.items():
                    if struct in line and data["size"] is not None:
                        
                        parts = line.split(None, 1)
                        if len(parts) >= 2:
                            vals = [v.strip() for v in parts[1].split(',') if v.strip()]
                            for v in vals:
                                val = int(v, 0)
                                size = data["size"]
                                data_address += size
                        else:
                            
                            size = data["size"]
                            data_address += size
                        break

            i += 1
            continue

        if in_text:
            
            if line.startswith('.global') or line.startswith('#'):
                i += 1
                continue

            # Check for labels
            if ':' in line:
                label_name = line.split(':', 1)[0].strip()
                labels[label_name] = text_address
                rest = line.split(':', 1)[1].strip()
                if rest and not rest.startswith('#') and not rest.startswith('.'):
                    text_address += 4
            
            elif not line.startswith('.'):
                text_address += 4

            i += 1

            continue

        i += 1

    return labels, entry_label

#Second Pass
def mainScan(labels, lines, text_base=TEXT_BASE, entry_label=None):
    instructions = []
    addr = text_base
    in_text = False
    # If entry_label maps to a known address then we use that as starting address
    start_addr = labels.get(entry_label) if entry_label else None

    for i, raw in enumerate(lines):
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue

        # section switches
        if line.startswith('.data'):
            in_text = False
            continue
        m_glob = re.match(r'^\.(?:global|globl)\b(?:\s+(?P<label>[A-Za-z_]\w*))?', line)
        if line.startswith('.text') or m_glob:
            # update start label if present and not already provided
            if m_glob and m_glob.group('label') and entry_label is None:
                entry_label = m_glob.group('label')
                start_addr = labels.get(entry_label)
            in_text = True
            continue

        if not in_text:
            continue

        # remove leading label if present
        if ':' in line:
            label_part, rest = line.split(':', 1)
            label_name = label_part.strip()
            rest = rest.strip()
            if start_addr is not None and addr < start_addr:
                if label_name == entry_label and rest:
                    line = rest
                else:
                    # skip label-only or label before entry point
                    if not rest:
                        continue
                    continue
            if not rest:
                # label-only line
                continue
            line = rest

        if line.startswith('.'):
            continue

        token = parse_instruction(line)
        if token:
            if start_addr is not None and addr < start_addr:
                addr += 4
                continue
            instructions.append({'addr': addr, 'line_no': i, 'raw': raw.rstrip('\n'), 'token': token})
            addr += 4

    return instructions


def tokenize_operand(op):
    op = op.strip()

    m = MEM_RE.match(op)
    if m:
        off_raw = m.group("off")
        base = m.group("base")
        return {
            "type": "mem",
            "offset_raw": off_raw,
            "offset": int(off_raw, 0),
            "base": base,
            "base_num": register_num(base),
            "raw": op
        }

    m2 = SYMPART_RE.match(op)
    if m2:
        return {
            "type": "symbol_part",
            "part": m2.group("part"),
            "symbol": m2.group("sym"),
            "raw": op
        }

    regnum = register_num(op)
    if regnum is not None:
        return {"type": "reg", "reg": op, "regnum": regnum, "raw": op}

    if IMM_RE.match(op):
        return {"type": "imm", "raw": op, "value": int(op, 0)}

    if SYM_RE.match(op):
        return {"type": "symbol", "name": op, "raw": op}

    return {"type": "unknown", "raw": op}



def parse_instruction(line):
    """Turn an instruction line (no label) into opcode + operand list + parsed operands."""
    line = line.split('#', 1)[0].strip()
    if not line:
        return None

    parts = line.split(None, 1)
    opcode = parts[0].lower()
    operands = []
    if len(parts) > 1:
        # split operands by commas
        operands = [o.strip() for o in parts[1].split(',') if o.strip()]

    parsed_operands = [tokenize_operand(o) for o in operands]

    return {'opcode': opcode, 'operands': operands, 'parsed': parsed_operands}

def register_num(reg):
    """Convert register name (string) to register number. Returns None for unknown names."""
    if reg is None:
        return None
    name = str(reg).strip().lower()
    Register = {
        'zero': 0, 'x0': 0,
        'ra': 1, 'x1': 1,
        'sp': 2, 'x2': 2,
        'gp': 3, 'x3': 3,
        'tp': 4, 'x4': 4,
        't0': 5, 'x5': 5,
        't1': 6, 'x6': 6,
        't2': 7, 'x7': 7,
        's0': 8, 'fp': 8, 'x8': 8,
        's1': 9, 'x9': 9,
        'a0': 10, 'x10': 10,
        'a1': 11, 'x11': 11,
        'a2': 12, 'x12': 12,
        'a3': 13, 'x13': 13,
        'a4': 14, 'x14': 14,
        'a5': 15, 'x15': 15,
        'a6': 16, 'x16': 16,
        'a7': 17, 'x17': 17,
        's2': 18, 'x18': 18,
        's3': 19, 'x19': 19,
        's4': 20, 'x20': 20,
        's5': 21, 'x21': 21,
        's6': 22, 'x22': 22,
        's7': 23, 'x23': 23,
        's8': 24, 'x24': 24,
        's9': 25, 'x25': 25,
        's10': 26, 'x26': 26,
        's11': 27, 'x27': 27,
        't3': 28, 'x28': 28,
        't4': 29, 'x29': 29,
        't5': 30, 'x30': 30,
        't6': 31, 'x31': 31,
    }

    return Register.get(name, None)


#Encoding helpers

def fits_signed(value, bits):
    return -(1 << (bits-1)) <= value <= (1 << (bits-1)) - 1


def encode_r(rd, rs1, rs2, funct7, funct3, opcode):
    return ((funct7 & 0x7f) << 25) | ((rs2 & 0x1f) << 20) | ((rs1 & 0x1f) << 15) | ((funct3 & 0x7) << 12) | ((rd & 0x1f) << 7) | (opcode & 0x7f)


def encode_i(rd, rs1, imm, funct3, opcode, funct7=None, is_shift=False):
    if is_shift:
        shamt = imm & 0x1f
        f7 = funct7 if funct7 is not None else 0
        return ((f7 & 0x7f) << 25) | ((shamt & 0x1f) << 20) | ((rs1 & 0x1f) << 15) | ((funct3 & 0x7) << 12) | ((rd & 0x1f) << 7) | (opcode & 0x7f)

    if not fits_signed(imm, 12):
        raise ValueError(f"Immediate {imm} out of range for 12-bit signed field")
    imm12 = imm & 0xfff
    return (imm12 << 20) | ((rs1 & 0x1f) << 15) | ((funct3 & 0x7) << 12) | ((rd & 0x1f) << 7) | (opcode & 0x7f)


def encode_s(rs2, rs1, imm, funct3, opcode):
    if not fits_signed(imm, 12):
        raise ValueError(f"Immediate {imm} out of range for S-type 12-bit signed field")
    imm12 = imm & 0xfff
    imm11_5 = (imm12 >> 5) & 0x7f
    imm4_0 = imm12 & 0x1f
    return (imm11_5 << 25) | ((rs2 & 0x1f) << 20) | ((rs1 & 0x1f) << 15) | ((funct3 & 0x7) << 12) | (imm4_0 << 7) | (opcode & 0x7f)


def encode_b(rs1, rs2, offset, funct3, opcode):
    if offset % 2 != 0:
        raise ValueError("Branch target offset must be multiple of 2")
    imm = offset >> 1
    if not fits_signed(imm, 12):
        raise ValueError(f"Branch offset {offset} out of range")
    imm &= 0xfff
    imm12 = (imm >> 11) & 0x1
    imm11 = (imm >> 10) & 0x1
    imm10_5 = (imm >> 4) & 0x3f
    imm4_1 = imm & 0xf
    return (imm12 << 31) | (imm10_5 << 25) | ((rs2 & 0x1f) << 20) | ((rs1 & 0x1f) << 15) | ((funct3 & 0x7) << 12) | (imm4_1 << 8) | (imm11 << 7) | (opcode & 0x7f)


def encode_u(rd, imm20, opcode):
    imm20 &= 0xfffff
    return (imm20 << 12) | ((rd & 0x1f) << 7) | (opcode & 0x7f)


def encode_j(rd, offset, opcode):
    if offset % 2 != 0:
        raise ValueError("JAL target offset must be multiple of 2")
    imm = offset >> 1
    if not fits_signed(imm, 20):
        raise ValueError(f"JAL offset {offset} out of range")
    imm &= 0xfffff
    imm20 = (imm >> 19) & 0x1
    imm10_1 = imm & 0x3ff
    imm11 = (imm >> 10) & 0x1
    imm19_12 = (imm >> 11) & 0xff
    return (imm20 << 31) | (imm10_1 << 21) | (imm11 << 20) | (imm19_12 << 12) | ((rd & 0x1f) << 7) | (opcode & 0x7f)


# Resolve %hi/%lo following the common assembler convention
def resolve_hi_lo(symbol_addr):
    hi = (symbol_addr + 0x800) >> 12
    lo = symbol_addr - (hi << 12)
    # ensure lo fits signed 12-bit
    if not fits_signed(lo, 12):
        lo &= 0xfff
    return hi, lo


def encode_instruction(token, labels, addr):
    op = token['opcode']
    parsed = token['parsed']

    # R-type
    if op in R_TYPE:
        rd = parsed[0]['regnum']
        rs1 = parsed[1]['regnum']
        rs2 = parsed[2]['regnum']
        info = R_TYPE[op]
        return encode_r(rd, rs1, rs2, info['funct7'], info['funct3'], info['opcode'])

    # I-type ALU
    if op in I_TYPE_ALU:
        rd = parsed[0]['regnum']
        rs1 = parsed[1]['regnum']
        imm_parsed = parsed[2]
        if imm_parsed['type'] == 'symbol_part' and imm_parsed['part'] == 'lo':
            sym = imm_parsed['symbol']
            if sym not in labels:
                raise ValueError(f"Unknown symbol: {sym}")
            hi, lo = resolve_hi_lo(labels[sym])
            imm = lo
        elif imm_parsed['type'] == 'imm':
            imm = imm_parsed['value']
        else:
            raise ValueError(f"Unsupported immediate form for {op}: {imm_parsed}")
        info = I_TYPE_ALU[op]
        return encode_i(rd, rs1, imm, info['funct3'], info['opcode'])

    # I-type shift
    if op in I_TYPE_SHIFT:
        rd = parsed[0]['regnum']
        rs1 = parsed[1]['regnum']
        shamt = parsed[2]['value']
        info = I_TYPE_SHIFT[op]
        return encode_i(rd, rs1, shamt, info['funct3'], info['opcode'], funct7=info['funct7'], is_shift=True)

    # I-type load
    if op in I_TYPE_LOAD:
        rd = parsed[0]['regnum']
        mem = parsed[1]
        rs1 = mem['base_num']
        imm = mem['offset']
        info = I_TYPE_LOAD[op]
        return encode_i(rd, rs1, imm, info['funct3'], info['opcode'])

    # S-type store
    if op in S_TYPE_STORE:
        rs2 = parsed[0]['regnum']
        mem = parsed[1]
        rs1 = mem['base_num']
        imm = mem['offset']
        info = S_TYPE_STORE[op]
        return encode_s(rs2, rs1, imm, info['funct3'], info['opcode'])

    # B-type branch
    if op in B_TYPE_BRANCH:
        rs1 = parsed[0]['regnum']
        rs2 = parsed[1]['regnum']
        sym = parsed[2]
        if sym['type'] != 'symbol':
            raise ValueError('Branch target must be a label')
        if sym['name'] not in labels:
            raise ValueError(f"Unknown label: {sym['name']}")
        target = labels[sym['name']]
        offset = target - addr
        info = B_TYPE_BRANCH[op]
        return encode_b(rs1, rs2, offset, info['funct3'], info['opcode'])

    # U-type 
    if op in U_TYPE:
        rd = parsed[0]['regnum']
        operand = parsed[1]
        if operand['type'] == 'symbol_part' and operand['part'] == 'hi':
            sym = operand['symbol']
            if sym not in labels:
                raise ValueError(f"Unknown symbol: {sym}")
            hi, lo = resolve_hi_lo(labels[sym])
            imm20 = hi
        elif operand['type'] == 'imm':
            imm20 = operand['value'] >> 12
        else:
            raise ValueError(f"Unsupported U-type operand: {operand}")
        info = U_TYPE[op]
        return encode_u(rd, imm20, info['opcode'])

    # jal
    if op in J_TYPE:
        rd = parsed[0]['regnum']
        sym = parsed[1]
        if sym['type'] != 'symbol':
            raise ValueError('JAL target must be a label')
        if sym['name'] not in labels:
            raise ValueError(f"Unknown label: {sym['name']}")
        target = labels[sym['name']]
        offset = target - addr
        info = J_TYPE[op]
        return encode_j(rd, offset, info['opcode'])

    # jalr
    if op in I_TYPE_JALR:
        rd = parsed[0]['regnum']
        mem = parsed[1]
        if mem['type'] != 'mem':
            raise ValueError('jalr expects imm(reg) operand')
        rs1 = mem['base_num']
        imm = mem['offset']
        info = I_TYPE_JALR[op]
        return encode_i(rd, rs1, imm, info['funct3'], info['opcode'])

    # system (ecall/ebreak)
    if op in I_TYPE_SYSTEM:
        info = I_TYPE_SYSTEM[op]
        return (info['imm12'] << 20) | (info['opcode'] & 0x7f)

    raise ValueError(f"Unsupported opcode: {op}")


def second_pass(instructions, labels):
    machine = []
    for inst in instructions:
        addr = inst['addr']
        token = inst['token']
        word = encode_instruction(token, labels, addr)  
        machine.append(word)
    return machine



def main():
    if len(sys.argv) != 3:
        print("Usage: python assembler.py <basePath> <asmFile>")
        sys.exit(1)

    basePath = sys.argv[1]
    asmFile = sys.argv[2]
    asmPath = os.path.join(basePath, asmFile)
    out_prefix = os.path.splitext(asmFile)[0]

    with open(asmPath, 'r') as f:
        lines = f.readlines()

    # First pass: labels + entry label
    labels, entry_label = initialScan(lines)

    # Second pass: tokenize instructions starting at entry label
    instructions = mainScan(labels, lines, text_base=TEXT_BASE, entry_label=entry_label)

    # Encode
    words = second_pass(instructions, labels)

    # Write required outputs
    hex_path = os.path.join(basePath, out_prefix + ".hex.txt")
    with open(hex_path, "w") as f:
        for w in words:
            f.write(f"0x{w:08x}\n")

    bin_path = os.path.join(basePath, out_prefix + ".bin")
    # Write raw binary in little-endian (4 bytes per instruction)
    with open(bin_path, "wb") as f:
        for w in words:
            f.write((w).to_bytes(4, byteorder='little', signed=False))


if __name__ == "__main__":
    main()


        

