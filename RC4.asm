;=====================================================================================================
; db là define byte ứng với 1 ký tự = 1 byte
; times là thao tác lặp đi lặp lại 256 lần như nhau
; có 3 loại là cl (bit thấp 8 bit ), ch (bit cao 8 bit),  cx là ghép của ch và cl nó lấy 16 bit
; jne = jump if Not Equal nhảy nếu A != B
; x and 0xFF là giữ lại 8 bit thấp nhất của x hay x thuộc 0->255
;=====================================================================================================
[BITS 32]
[extern GetStdHandle]  
[extern ReadConsoleA]
[extern WriteConsoleA]
[extern ExitProcess]

[section .data]
    msg_input     db "Enter plaintext: ", 0   
    msg_key       db "Enter key: ", 0
    newline       db 0Ah, 0

    buffer_input  times 256 db 0    ; phần mảng nhập input
    buffer_output times 512 db 0    ; 256 bytes input → 512 ký tự hex 
    buffer_key    times 256 db 0    ; phần mảng nhập key
    S             times 256 db 0    ; S-box: mảng 256 byte
    temp                    db 0    ; biến tạm dùng khi hoán đổi
    hex_table db '0123456789ABCDEF'

[section .bss]
    hInput    resd 1
    hOutput   resd 1
    bytesRead resd 1
   ;temp      resd 1 cũng được nếu muốn ngắn gọn 
[section .text]
global Start
Start:
    ; GetStdHandle(STD_OUTPUT_HANDLE = -11) 
    push -11
    call GetStdHandle
    mov [hOutput], eax

    ; GetStdHandle(STD_INPUT_HANDLE = -10) 
    push -10
    call GetStdHandle
    mov [hInput], eax

    ; WriteConsoleA(hOutput, msg_input, 17, &bytesRead, 0) 
    push 0
    push bytesRead
    push 17
    push msg_input
    push dword [hOutput]
    call WriteConsoleA

    ; ReadConsoleA(hInput, buffer_input, 256, &bytesRead, 0) 
    push 0
    push bytesRead
    push 256
    push buffer_input
    push dword [hInput]
    call ReadConsoleA

    ; WriteConsoleA(hOutput, msg_key, 10, &bytesRead, 0) 
    push 0
    push bytesRead
    push 10
    push msg_key
    push dword [hOutput]
    call WriteConsoleA

    ; ReadConsoleA(hInput, buffer_key, 256, &bytesRead, 0) 
    push 0
    push bytesRead
    push 256
    push buffer_key
    push dword [hInput]
    call ReadConsoleA
    ; Solve in here 
    init_sbox:                ; khoi tao cho mang S
    xor ecx, ecx              ; ecx = i = 0  
.init_loop:
    mov [S + ecx], cl         ; S[i] = i  // cl = ecx = i
    inc ecx                   ; ecx++
    cmp ecx, 256              ; so sánh ecx với 256
    jne .init_loop            ; bước nhảy sẽ được thực hiện nếu ecx != 256

    xor ecx, ecx              ; i = 0
    xor edi, edi              ; j = 0

.ksa_loop:
    movzx eax, byte [S + ecx]     ; eax = S[i]  // chuyển giá trị từ byte [S + ecx] vào eax và điền thêm các bit cao bằng 0.
    movzx ebx, byte [buffer_key + ecx]  ; ebx = key[i] // chuyển giá trị từ byte [buffer_key + ecx] vào ebx và điền thêm các bit cao bằng 0.
    add edi, eax               ; edi += eax
    add edi, ebx               ; edi += ebx
    and edi, 0xFF              ; j = (j + S[i] + key[i]) % 256

    ; hoán đổi S[i] và S[j]
    mov al, [S + ecx]          ; al = s[i]
    mov bl, [S + edi]          ; bl = s[j]
    mov [S + ecx], bl          ; s[i] = bl
    mov [S + edi], al          ; s[j] = al

    inc ecx                    ; ecx++
    cmp ecx, 256               ; so sánh ecx với 256
    jne .ksa_loop
;=====================================================================================================================
    call prga_encrypt
    call print_hex_output
    prga_encrypt:
    xor ecx, ecx        ; ecx = i = 0
    xor edi, edi        ; edi = j = 0
    xor esi, esi        ; esi = offset đếm ký tự đang xử lý (n)

.encrypt_loop:
    ; i = (i + 1) % 256
    inc ecx              ; ecx++
    and ecx, 0xFF        ; giữ ecx trong khoảng 0–>255

    ; j = (j + S[i]) % 256
    movzx eax, byte [S + ecx]  ; eax = S[i]
    add edi, eax               ; edi += eax
    and edi, 0xFF              ; giữ j trong khoảng 0->255

    ; hoán đổi S[i] và S[j]
    mov al, [S + ecx]          ; al = s[i]
    mov bl, [S + edi]          ; bl = s[j]
    mov [S + ecx], bl          ; s[i] = bl
    mov [S + edi], al          ; s[j] = al

    ; t = (S[i] + S[j]) % 256
    movzx eax, byte [S + ecx]  ; eax = s[i]
    movzx ebx, byte [S + edi]  ; ebx = s[j]
    add eax, ebx               ; eax += ebx
    and eax, 0xFF              ; giữ t trong khoảng 0–>255

    ; K = S[t]
    mov bl, [S + eax]    ; bl = byte keystream

    ; XOR với plaintext để mã hóa
    mov al, [buffer_input + esi] ; al = ký tự plaintext
    xor al, bl                   ; al = mã hóa
    mov [buffer_input + esi], al ; ghi lại kết quả vào chính buffer_input

    ; tăng biến đếm
    inc esi                      ; esi++
    cmp esi, [bytesRead]         ; kiểm tra đã hết chưa
    jb .encrypt_loop             ; nếu chưa hết thì tiếp tục vòng lặp

;==================================================================================================================
    print_hex_output:
    xor ecx, ecx             ; ecx = offset = 0
.loop:
    movzx eax, byte [buffer_input + ecx]  
    mov ebx, eax             ; lưu lại byte

    shr al, 4                ; lấy 4 bit cao
    mov dl, [hex_table + eax]
    mov [buffer_output + ecx*2], dl

    mov al, bl               ; khôi phục lại byte ban đầu
    and al, 0Fh              ; lấy 4 bit thấp
    mov dl, [hex_table + eax]
    mov [buffer_output + ecx*2 + 1], dl

    inc ecx                  ; ecx++
    cmp ecx, [bytesRead]     ; so sánh ecx với phần từ đầu tiên của bytesRead
    jb .loop

    ; In ra màn hình
    push 0                  ; reserved
    push bytesRead          ; số ký tự gốc
    mov eax, [bytesRead]    ; eax = bytesRead
    shl eax, 1
    push eax                ;
    push buffer_output      ; buffer chứa hex
    push dword [hOutput]          ; handle output
    call WriteConsoleA

  

    ; ExitProcess(0)
    push 0
    call ExitProcess
    