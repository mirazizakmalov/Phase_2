import sys
import os
import re
# Data Type Sizes
DATA_TYPES = {
    ".byte": {"size": 1,}, 
    ".half": {"size": 2,},
    ".word": {"size": 4,}, 
    ".dword": {"size": 8,}, 
    ".float": {"size": 4,},
    ".double": {"size": 8,},
    ".space": {"size": None,}, # Size is variable
    ".ascii": {"size": None,}, # Size is variable based on length of the string
    ".asciz": {"size": None,} # Size is variable, null-terminated
}


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
    mem = 0
    labels = {}
    ProCount ={}
    text_address = 0x00000000
    i = 0
    
    # .data section
    while i < len(lines):
        line = lines[i].strip()
        
        if line.startswith(".data"):
            i += 1
            continue
        
        # Stop data check
        if line.startswith(".text") or line.startswith(".global"):
            break
        
        if line and not line.startswith('#'):
            # ASCII handling
            if '.ascii' in line:
                # General ASCII patter I.E "stuff"
                match = re.search(r'"([^"]*)"', line) 
                if match:
                    mem += len(match.group(1))
                    if '.asciiz' in line:
                        mem += 1
            
            # Handle .space separately
            elif '.space' in line:
                parts = line.split()
                if len(parts) >= 2:
                    mem += int(parts[1])
            
            # Handle fixed-size directives
            else:
                for struct, data in DATA_TYPES.items():
                    if struct in line and data["size"] is not None:
                        mem += data["size"]
                        break
        
        i += 1
    
    # .text section
    while i < len(lines):
        line = lines[i].strip()
        
        if not line or line.startswith('#') or line.startswith('.global'): # So we can be safe!
            i += 1
            continue
        
        # Check for labels
        if ':' in line:
            label_name = line.split(':')[0].strip()
            labels[label_name] = text_address # Stores the address and label 
            # Check for instruction on same line
            rest = line.split(':', 1)[1].strip()
            if rest and not rest.startswith('#') and not rest.startswith('.'):
                text_address += 4
        # Regular instruction
        elif not line.startswith('.'):
            text_address += 4
        
        ProcCount[lines[i]] = text_address
        i += 1
    
    return mem, labels

def main():
    basePath = sys.argv[1]
    asmFile = sys.argv[2]
    asmPath = os.path.join(basePath, asmFile)
    
    #Read assembly file
    with open(asmPath, 'r') as f:
        lines = f.readlines()

    mem, labels = initialScan(lines)
            

if __name__ == "__main__":
    main()
        

