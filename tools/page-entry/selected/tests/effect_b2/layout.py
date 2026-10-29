"""File-only actual DWARF, never executes the inferior."""
import gdb,json
names=('be_record','be_row','b2_snapshot','b2_format_record','b2_format_sample',
 'li2_effect_owner','li2_effect_input','li2_effect_binding','li2_effect_decision',
 'li2_effect_result','li2_effect_fault','li2_effect_state','li2_effect_xstate',
 'li2_effect_source','li2_decoded','li2_selected_completion','li2_selected_hardware',
 'selected_builtin_prefix','li2_oneshot_plan','li2_oneshot_page')
result={}
for name in names:
 t=gdb.lookup_type('struct '+name)
 result[name]={'bytes':int(t.sizeof),'fields':{f.name:{'offset':int(f.bitpos)//8,'bytes':int(f.type.sizeof)}for f in t.fields()}}
u=gdb.lookup_type('ucontext_t');m=next(f for f in u.fields()if f.name=='uc_mcontext');mt=m.type
result['layout']={'uc_bytes':int(u.sizeof),'greg':int(m.bitpos)//8+int(next(f for f in mt.fields()if f.name=='gregs').bitpos)//8,
 'fp_pointer':int(m.bitpos)//8+int(next(f for f in mt.fields()if f.name=='fpregs').bitpos)//8,
 'sigmask':int(next(f for f in u.fields()if f.name=='uc_sigmask').bitpos)//8}
result['symbols']={name:int(gdb.parse_and_eval('(uintptr_t)&'+name))for name in
 ('be_record','b2_format_record','be_policy_callback','be_policy_post','be_policy_context')}
print(json.dumps(result,sort_keys=True))
