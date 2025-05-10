#!/usr/bin/env python3
import os, sys, re

# Paths (adjust if you moved things)
HERE = os.path.dirname(__file__)
SRC  = os.path.normpath(os.path.join(HERE, '..', 'src', 'blowfish.c'))
OUT_DIR = os.path.normpath(os.path.join(HERE, '..', 'include'))
OUT_H   = os.path.join(OUT_DIR, 'blowfish_tables.h')

def extract_array(data, name):
    """
    Find the C array named `name` in data,
    return the full brace-enclosed initializer (including inner braces).
    """
    # locate start
    m = re.search(r'static\s+const\s+[^\n]*?' + re.escape(name), data)
    if not m:
        sys.exit(f"Error: `{name}` not found in src/blowfish.c")
    start = data.find('{', m.end())
    if start < 0:
        sys.exit(f"Error: opening '{{' for {name} not found")
    # walk braces
    depth = 0
    for i in range(start, len(data)):
        if data[i] == '{':
            depth += 1
        elif data[i] == '}':
            depth -= 1
            if depth == 0:
                return data[start:i+1]
    sys.exit(f"Error: closing '}}' for {name} not found")

def main():
    code = open(SRC, 'r').read()
    # extract _BLOWFISH_PArray and _BLOWFISH_SBox
    parr = extract_array(code, '_BLOWFISH_PArray')
    sbox = extract_array(code, '_BLOWFISH_SBox')
    # build output
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(OUT_H, 'w') as f:
        f.write(f"""#ifndef BLOWFISH_TABLES_H
#define BLOWFISH_TABLES_H

#include <stdint.h>

/* ----------------------------------------------------------------
 * Generated from src/blowfish.c’s
 *   static const _BLOWFISH_PArray[...] and
 *   static const _BLOWFISH_SBox[...] arrays
 * Remapped here as ORIG_P and ORIG_S for
 * use in our blowfish.c driver.
 * ----------------------------------------------------------------
 */
static const uint32_t ORIG_P[18] = {parr};

static const uint32_t ORIG_S[4][256] = {sbox};

#endif /* BLOWFISH_TABLES_H */
""")
    print(f"Wrote {OUT_H}")

if __name__ == '__main__':
    main()

