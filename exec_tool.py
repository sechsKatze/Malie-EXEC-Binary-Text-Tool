import struct
import json
import sys

ALIGN = 8

# ----------------------------
# 내부 유틸
# ----------------------------
def read_u16(data, off):
    return struct.unpack_from("<H", data, off)[0]

def align_up(x, a):
    r = x % a
    return x if r == 0 else x + (a - r)

# ----------------------------
# 문자열 슬롯 탐지기
# ----------------------------
def scan_string_slots(payload: bytes, entry_abs_start: int):
    slots = []
    i = 0
    n = len(payload)
    while i + 2 <= n:
        start = i
        chars = []
        valid = False
        while i + 2 <= n:
            w = read_u16(payload, i)
            i += 2
            if w == 0:
                valid = True
                break
            chars.append(chr(w))
        if valid:
            text = "".join(chars)
            slot_len = i - start
            slots.append({
                "rel_off": start,
                "byte_len": slot_len,
                "text": text
            })
        else:
            break
        if len(slots) > 100000:
            break
        if slot_len == 2 and i < n and payload[i:i+8] == b"\x00"*8:
            pass
        if i <= start:
            i += 2
    return slots

# ----------------------------
# 디스어셈블: 문자열 슬롯 메타 추출
# ----------------------------
def disassemble_exec(exec_path: str, json_path: str):
    with open(exec_path, "rb") as f:
        data = f.read()

    entries = []
    off = 0
    size = len(data)

    while off + 8 <= size:
        try:
            eid, flags = struct.unpack_from("<II", data, off)
        except struct.error:
            break

        payload_start = off + 8
        payload = data[payload_start:]
        slots = scan_string_slots(payload, off)

        if slots:
            last = slots[-1]
            payload_end_rel = last["rel_off"] + last["byte_len"]
        else:
            payload_end_rel = 0

        entry_end = payload_start + payload_end_rel
        entry_end_aligned = align_up(entry_end, ALIGN)

        if entry_end_aligned <= off:
            break
        if entry_end_aligned > size:
            entry_end_aligned = size

        entries.append({
            "id": eid,
            "flags": flags,
            "strings": [s["text"] for s in slots],
            "_slots": slots,
            "_entry_abs_start": off,
            "_entry_abs_end": entry_end_aligned
        })

        off = entry_end_aligned
        if off >= size:
            break

    # --- UTF-16LE 고정 저장 ---
    json_text = json.dumps(entries, ensure_ascii=False, indent=2)
    json_text = json_text.replace("\n", "\r\n")  # VS Code가 binary로 오판하지 않게 CRLF로 변환
    encoded = json_text.encode("utf-16le", errors="surrogatepass")

    with open(json_path, "wb") as f:
        f.write(b"\xff\xfe")  # UTF-16 LE BOM
        f.write(encoded)

    print(f"[+] 디스어셈블 완료: {len(entries)} entries → {json_path}")

# ----------------------------
# 어셈블(인플레이스 패치)
# ----------------------------
def assemble_inplace(original_exec_path: str, json_path: str, output_exec_path: str):
    with open(original_exec_path, "rb") as f:
        data = bytearray(f.read())

    # --- UTF-16LE 고정 읽기 ---
    with open(json_path, "rb") as f:
        raw = f.read()
    try:
        text = raw.decode("utf-16le", errors="surrogatepass")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="ignore")

    entries = json.loads(text)

    if not entries or "_slots" not in entries[0]:
        raise RuntimeError("이 JSON에는 슬롯 메타(_slots)가 없습니다. 반드시 본 도구의 disassemble로 만든 JSON을 사용하세요.")

    patched = 0
    for e in entries:
        slots = e.get("_slots", [])
        if not slots:
            continue

        new_strings = e.get("strings", [])
        if len(new_strings) != len(slots):
            raise RuntimeError(f"Entry ID={e.get('id')} 문자열 개수 불일치: slots={len(slots)} vs strings={len(new_strings)}")

        entry_payload_abs = e["_entry_abs_start"] + 8

        for slot, new_text in zip(slots, new_strings):
            rel_off = slot["rel_off"]
            cap_len = slot["byte_len"]
            abs_off = entry_payload_abs + rel_off

            enc = new_text.encode("utf-16le", errors="surrogatepass") + b"\x00\x00"
            if len(enc) > cap_len:
                over = len(enc) - cap_len
                raise RuntimeError(
                    f"문자열 길이 초과: ID={e.get('id')} 오프셋=0x{abs_off:x} "
                    f"슬롯용량={cap_len}B, 새문자열={len(enc)}B, 초과={over}B → "
                    f"번역문을 줄이거나 슬롯을 나누어주세요."
                )
            data[abs_off:abs_off+cap_len] = enc + b"\x00" * (cap_len - len(enc))
            patched += 1

    with open(output_exec_path, "wb") as f:
        f.write(data)

    print(f"[+] 어셈블(인플레이스) 완료 → {output_exec_path}")
    print(f"    패치된 문자열 슬롯 수: {patched}")
    print(f"    파일 크기: {len(data)} (원본과 동일해야 정상)")

# ----------------------------
# BIN 직복사
# ----------------------------
def export_bin(exec_path: str, bin_path: str):
    with open(exec_path, "rb") as src, open(bin_path, "wb") as dst:
        dst.write(src.read())
    print(f"[+] EXEC → BIN 변환 완료 → {bin_path}")

def import_bin(bin_path: str, exec_path: str):
    with open(bin_path, "rb") as src, open(exec_path, "wb") as dst:
        dst.write(src.read())
    print(f"[+] BIN → EXEC 변환 완료 → {exec_path}")

# ----------------------------
# 검증
# ----------------------------
def verify_exec(orig_path: str, new_path: str):
    with open(orig_path, "rb") as f1, open(new_path, "rb") as f2:
        d1, d2 = f1.read(), f2.read()
    if d1 == d2:
        print("[✓] EXEC 완전 일치 (byte-perfect)")
    else:
        print(f"[✗] EXEC 불일치 — 크기 {len(d1)} vs {len(d2)} / 차이 {len(d1)-len(d2)}")

# ----------------------------
# 메인
# ----------------------------
def main():
    if len(sys.argv) < 2:
        print("사용법:")
        print("  python exec_tool.py disassemble EXEC output.json")
        print("  python exec_tool.py assemble-inplace ORIGINAL.EXEC edited.json output.EXEC")
        print("  python exec_tool.py export-bin EXEC output.bin")
        print("  python exec_tool.py import-bin input.bin output.EXEC")
        print("  python exec_tool.py verify original.EXEC new.EXEC")
        sys.exit(1)

    mode = sys.argv[1].lower()
    if mode == "disassemble":
        if len(sys.argv) < 4:
            print("예: python exec_tool.py disassemble EXEC output.json"); sys.exit(1)
        disassemble_exec(sys.argv[2], sys.argv[3])

    elif mode == "assemble-inplace":
        if len(sys.argv) < 5:
            print("예: python exec_tool.py assemble-inplace ORIGINAL.EXEC edited.json output.EXEC"); sys.exit(1)
        assemble_inplace(sys.argv[2], sys.argv[3], sys.argv[4])

    elif mode == "export-bin":
        export_bin(sys.argv[2], sys.argv[3])

    elif mode == "import-bin":
        import_bin(sys.argv[2], sys.argv[3])

    elif mode == "verify":
        verify_exec(sys.argv[2], sys.argv[3])

    else:
        print(f"[!] 알 수 없는 명령: {mode}")

if __name__ == "__main__":
    main()
