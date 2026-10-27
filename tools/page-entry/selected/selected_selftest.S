.text
.global selected_selftest_enter
.hidden selected_selftest_enter
.type selected_selftest_enter,@function
selected_selftest_enter:
    pushfq
    popq selected_selftest_flags(%rip)
    call *%rdi
    ret
.size selected_selftest_enter,.-selected_selftest_enter
.global selected_selftest_return
.hidden selected_selftest_return
.type selected_selftest_return,@function
selected_selftest_return:
    ret
.size selected_selftest_return,.-selected_selftest_return
.hidden selected_selftest_flags
.section .note.GNU-stack,"",@progbits
