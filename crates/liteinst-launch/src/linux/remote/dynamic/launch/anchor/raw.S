.text
.p2align 4
.global li2_anchor_code_begin
.hidden li2_anchor_code_begin
li2_anchor_code_begin:
.global li2_anchor_enter
.hidden li2_anchor_enter
.type li2_anchor_enter,@function
li2_anchor_enter:
    mov %rdi,%r12
    mov {stack_top}(%r12),%rsp
    and $-16,%rsp
    mov {parent_channel}(%r12),%rdi
    mov $3,%eax
    syscall
    test %rax,%rax
    jne li2_anchor_fail
    mov {parent_release}(%r12),%rdi
    mov $3,%eax
    syscall
    test %rax,%rax
    jne li2_anchor_fail
    mov {error_read}(%r12),%rdi
    mov $3,%eax
    syscall
    test %rax,%rax
    jne li2_anchor_fail
    mov $39,%eax
    syscall
    test %rax,%rax
    jle li2_anchor_fail
    mov %rax,{tid}(%r12)
    mov %rax,{prepared_tid}(%r12)
    mov %rax,{anchor_tid}(%r12)
    mov %eax,{signal_pid}(%r12)
    mov $2,%edi
    xor %esi,%esi
    lea {old_mask}(%r12),%rdx
    mov $8,%r10d
    mov $14,%eax
    syscall
    test %rax,%rax
    jne li2_anchor_fail
    movabs ${blocked},%rax
    cmp %rax,{old_mask}(%r12)
    jne li2_anchor_invalid
    xor %edi,%edi
    lea {old_stack}(%r12),%rsi
    mov $131,%eax
    syscall
    test %rax,%rax
    jne li2_anchor_fail
    mov ${probe},%edi
    xor %esi,%esi
    lea {old_action}(%r12),%rdx
    mov $8,%r10d
    mov $13,%eax
    syscall
    test %rax,%rax
    jne li2_anchor_fail
    lea {pending}(%r12),%rdi
    mov $8,%esi
    mov $127,%eax
    syscall
    test %rax,%rax
    jne li2_anchor_fail
    cmpq $0,{pending}(%r12)
    jne li2_anchor_invalid
    mov {channel}(%r12),%rdi
    lea {prepared}(%r12),%rsi
    mov $64,%edx
    mov $1,%eax
    syscall
.global li2_anchor_prepared_return
.hidden li2_anchor_prepared_return
li2_anchor_prepared_return:
    cmp $64,%rax
    jne li2_anchor_invalid
.global li2_anchor_pre_read
.hidden li2_anchor_pre_read
li2_anchor_pre_read:
    mov {release}(%r12),%rdi
    lea {release_byte}(%r12),%rsi
    mov $1,%edx
    mov $0,%eax
.global li2_anchor_read_insn
.hidden li2_anchor_read_insn
li2_anchor_read_insn:
    syscall
.global li2_anchor_read
.hidden li2_anchor_read
li2_anchor_read:
    cmp $1,%rax
    jne li2_anchor_invalid
    cmpb $0xa5,{release_byte}(%r12)
    jne li2_anchor_invalid
    mov {release}(%r12),%rdi
    mov $3,%eax
    syscall
.global li2_anchor_close_release
.hidden li2_anchor_close_release
li2_anchor_close_release:
    test %rax,%rax
    jne li2_anchor_fail
    mov ${probe},%edi
    lea {probe_action}(%r12),%rsi
    xor %edx,%edx
    mov $8,%r10d
    mov $13,%eax
    syscall
.global li2_anchor_install
.hidden li2_anchor_install
li2_anchor_install:
    test %rax,%rax
    jne li2_anchor_fail
    mov ${probe},%edi
    xor %esi,%esi
    lea {check_action}(%r12),%rdx
    mov $8,%r10d
    mov $13,%eax
    syscall
.global li2_anchor_query_installed
.hidden li2_anchor_query_installed
li2_anchor_query_installed:
    test %rax,%rax
    jne li2_anchor_fail
    lea {pending}(%r12),%rdi
    mov $8,%esi
    mov $127,%eax
    syscall
.global li2_anchor_pending_before
.hidden li2_anchor_pending_before
li2_anchor_pending_before:
    test %rax,%rax
    jne li2_anchor_fail
    cmpq $0,{pending}(%r12)
    jne li2_anchor_invalid
    mov {tid}(%r12),%rdi
    mov %rdi,%rsi
    mov ${probe},%edx
    lea {signal}(%r12),%r10
    mov $297,%eax
    syscall
.global li2_anchor_queue
.hidden li2_anchor_queue
li2_anchor_queue:
    test %rax,%rax
    jne li2_anchor_fail
    mov $2,%edi
    lea {probe_mask}(%r12),%rsi
    xor %edx,%edx
    mov $8,%r10d
    mov $14,%eax
    syscall
.global li2_anchor_unmask
.hidden li2_anchor_unmask
li2_anchor_unmask:
    # The pending signal must be delivered before this original fallthrough.
    jmp li2_anchor_invalid

.global li2_anchor_handler
.hidden li2_anchor_handler
.type li2_anchor_handler,@function
li2_anchor_handler:
    cmp ${probe},%edi
    jne li2_anchor_invalid
    cmp {stack_low}(%r12),%rsp
    jb li2_anchor_invalid
    lea 440(%rsp),%rax
    cmp {stack_top}(%r12),%rax
    ja li2_anchor_invalid
    lea 8(%rsp),%rax
    cmp %rax,%rdx
    jne li2_anchor_invalid
    lea 312(%rsp),%rax
    cmp %rax,%rsi
    jne li2_anchor_invalid
    mov %rsp,{frame}(%r12)
    mov %rdx,{ucontext}(%r12)
    mov %rsi,{siginfo}(%r12)
    # Signal entry clears DF; this loop touches only exact initialized words.
    xor %ecx,%ecx
1:
    mov (%rsi,%rcx,8),%rax
    cmp {signal}(%r12,%rcx,8),%rax
    jne li2_anchor_invalid
    inc %ecx
    cmp $16,%ecx
    jne 1b
    mov 200(%rdx),%rax
    mov %rax,{metadata}(%r12)
    mov 192(%rdx),%rax
    mov %rax,{metadata_error}(%r12)
    mov 216(%rdx),%rax
    mov %rax,{metadata_cr2}(%r12)
    mov $2,%edi
    lea {old_mask}(%r12),%rsi
    xor %edx,%edx
    mov $8,%r10d
    mov $14,%eax
    syscall
.global li2_anchor_reblock
.hidden li2_anchor_reblock
li2_anchor_reblock:
    test %rax,%rax
    jne li2_anchor_fail
    mov $2,%edi
    xor %esi,%esi
    lea {current_mask}(%r12),%rdx
    mov $8,%r10d
    mov $14,%eax
    syscall
.global li2_anchor_query_mask
.hidden li2_anchor_query_mask
li2_anchor_query_mask:
    test %rax,%rax
    jne li2_anchor_fail
    mov {old_mask}(%r12),%rax
    cmp %rax,{current_mask}(%r12)
    jne li2_anchor_invalid
    lea {pending}(%r12),%rdi
    mov $8,%esi
    mov $127,%eax
    syscall
.global li2_anchor_pending_restore
.hidden li2_anchor_pending_restore
li2_anchor_pending_restore:
    test %rax,%rax
    jne li2_anchor_fail
    cmpq $0,{pending}(%r12)
    jne li2_anchor_invalid
    mov ${probe},%edi
    lea {old_action}(%r12),%rsi
    xor %edx,%edx
    mov $8,%r10d
    mov $13,%eax
    syscall
.global li2_anchor_restore_action
.hidden li2_anchor_restore_action
li2_anchor_restore_action:
    test %rax,%rax
    jne li2_anchor_fail
    mov ${probe},%edi
    xor %esi,%esi
    lea {check_action}(%r12),%rdx
    mov $8,%r10d
    mov $13,%eax
    syscall
.global li2_anchor_query_restored
.hidden li2_anchor_query_restored
li2_anchor_query_restored:
    test %rax,%rax
    jne li2_anchor_fail
    lea {old_action}(%r12),%rsi
    lea {check_action}(%r12),%rdi
    mov $4,%ecx
    repe cmpsq
    jne li2_anchor_invalid
    xor %edi,%edi
    lea {check_stack}(%r12),%rsi
    mov $131,%eax
    syscall
.global li2_anchor_query_stack
.hidden li2_anchor_query_stack
li2_anchor_query_stack:
    test %rax,%rax
    jne li2_anchor_fail
    lea {old_stack}(%r12),%rsi
    lea {check_stack}(%r12),%rdi
    mov $3,%ecx
    repe cmpsq
    jne li2_anchor_invalid
    lea {pending}(%r12),%rdi
    mov $8,%esi
    mov $127,%eax
    syscall
.global li2_anchor_pending_after
.hidden li2_anchor_pending_after
li2_anchor_pending_after:
    test %rax,%rax
    jne li2_anchor_fail
    cmpq $0,{pending}(%r12)
    jne li2_anchor_invalid
    mov {channel}(%r12),%rdi
    lea {anchor}(%r12),%rsi
    mov $64,%edx
    mov $1,%eax
    syscall
.global li2_anchor_write_anchor
.hidden li2_anchor_write_anchor
li2_anchor_write_anchor:
    cmp $64,%rax
    jne li2_anchor_invalid
    mov {channel}(%r12),%rdi
    mov $3,%eax
    syscall
.global li2_anchor_close_channel
.hidden li2_anchor_close_channel
li2_anchor_close_channel:
    test %rax,%rax
    jne li2_anchor_fail
    mov {program}(%r12),%rdi
    mov {argv}(%r12),%rsi
    mov {envp}(%r12),%rdx
    mov $59,%eax
    syscall
.global li2_anchor_exec
.hidden li2_anchor_exec
li2_anchor_exec:
    # Any returning exec failure is terminal; never return to the helper caller.
    jmp li2_anchor_fail
.global li2_anchor_restorer
.hidden li2_anchor_restorer
li2_anchor_restorer:
    # A real ABI restorer address exists, but this protocol never returns here.
    jmp li2_anchor_invalid
li2_anchor_invalid:
    mov $-22,%rax
li2_anchor_fail:
    neg %eax
    movl $3,{error}(%r12)
    mov %eax,{error_errno}(%r12)
    mov {error_write}(%r12),%rdi
    lea {error}(%r12),%rsi
    mov $8,%edx
    mov $1,%eax
    syscall
2:
    mov $127,%edi
    mov $231,%eax
    syscall
    jmp 2b
.global li2_anchor_code_end
.hidden li2_anchor_code_end
li2_anchor_code_end:
