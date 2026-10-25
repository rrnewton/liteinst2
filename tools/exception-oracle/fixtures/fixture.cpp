// Authored fixture only: actual libstdc++ throw/personality/catch processing.
#include <cstdint>
#include <unwind.h>

extern "C" {
std::uint64_t liteinst_exception_pad_visits = 0;
std::uint64_t liteinst_exception_pad_rax = 0;
std::uint64_t liteinst_exception_pad_rdx = 0;
std::uint64_t liteinst_exception_search = 0;
std::uint64_t liteinst_exception_cleanup = 0;
std::uint64_t liteinst_exception_handler = 0;
std::uint64_t liteinst_exception_other = 0;
std::uint64_t liteinst_exception_personality_calls = 0;

_Unwind_Reason_Code __gxx_personality_v0(
    int, _Unwind_Action, _Unwind_Exception_Class, _Unwind_Exception *, _Unwind_Context *);

[[noreturn]] __attribute__((noinline, visibility("hidden")))
void liteinst_exception_throw(int value) {
    throw value;
}

__attribute__((noinline, visibility("hidden")))
_Unwind_Reason_Code liteinst_exception_personality(
    int version, _Unwind_Action actions, _Unwind_Exception_Class exception_class,
    _Unwind_Exception *exception, _Unwind_Context *context) noexcept {
    ++liteinst_exception_personality_calls;
    if (actions == _UA_SEARCH_PHASE) {
        ++liteinst_exception_search;
    } else if (actions == (_UA_CLEANUP_PHASE | _UA_HANDLER_FRAME)) {
        ++liteinst_exception_cleanup;
        ++liteinst_exception_handler;
    } else {
        ++liteinst_exception_other;
    }
    return __gxx_personality_v0(version, actions, exception_class, exception, context);
}
}
