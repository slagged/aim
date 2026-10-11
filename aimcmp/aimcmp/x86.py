"""Shared x86 register and operand semantics for evidence analysis."""


def canonical_register(name):
    for root, aliases in {
        'eax': ('eax', 'ax', 'al', 'ah'), 'ebx': ('ebx', 'bx', 'bl', 'bh'),
        'ecx': ('ecx', 'cx', 'cl', 'ch'), 'edx': ('edx', 'dx', 'dl', 'dh'),
        'esi': ('esi', 'si'), 'edi': ('edi', 'di'),
        'esp': ('esp', 'sp'), 'ebp': ('ebp', 'bp'),
    }.items():
        if name in aliases:
            return root
    return name


def signed32(value):
    value &= 0xffffffff
    return value - 0x100000000 if value & 0x80000000 else value


def stack_operand_width(instruction):
    # Immediate encoding width does not determine the architectural stack width.
    return 2 if 0x66 in instruction.prefix else 4
