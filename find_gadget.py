#!/usr/bin/env python3
import sys

try:
    with open("problem3", "rb") as f:
        data = f.read()
        base_address = 0x400000  # 可执行文件的常见基地址
        
        # 查找 pop rdi; ret (5f c3)
        for i in range(len(data) - 1):
            if data[i] == 0x5f and data[i+1] == 0xc3:  # pop rdi; ret
                gadget_address = base_address + i
                print(f"Found 'pop rdi; ret' at offset 0x{i:x}, address: 0x{gadget_address:x}")
                sys.exit(0)
        
        print("No 'pop rdi; ret' gadget found. Trying alternative search...")
        
        # 查找 pop rdi 后跟 ret 的序列，中间可能有其他指令
        for i in range(len(data) - 10):
            if data[i] == 0x5f:  # pop rdi
                # 查找接下来的 ret (c3)，允许中间有其他指令
                for j in range(i+1, min(i+10, len(data))):
                    if data[j] == 0xc3:  # ret
                        gadget_address = base_address + i
                        print(f"Found 'pop rdi' at offset 0x{i:x} followed by 'ret' at 0x{j:x}, address: 0x{gadget_address:x}")
                        break
                break
        else:
            print("No suitable gadget found.")
except FileNotFoundError:
    print("File 'problem3' not found. Make sure you're in the correct directory.")
except Exception as e:
    print(f"Error: {e}")
