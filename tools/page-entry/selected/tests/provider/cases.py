"""The complete finite native/scripted provider cohort; no execution on import."""

def cohort():
 regs=[i for i in range(16) if i!=4]
 operands=[(k,w,r) for k in (2,3) for w in (16,32,64) for r in regs]+[(4,64,r) for r in regs]
 cases=[]
 def add(name,args,status=0,cf0=False,reject=None):cases.append({'name':name,'args':args,'status':status,'cf0':cf0,'reject':reject})
 for kind,width,reg in operands:
  add(f'native-{kind}-{width}-{reg}',[1,kind,width,reg,0,0,0])
  add(f'script-{kind}-{width}-{reg}',[2,kind,width,reg,0,0,0])
  if kind!=4:add(f'script-cf0-{kind}-{width}-{reg}',[2,kind,width,reg,0,0,0],cf0=True)
 for kind,width in [(k,w) for k in (2,3) for w in (16,32,64)]+[(4,64)]:
  add(f'rsp-refusal-{kind}-{width}',[2,kind,width,4,0,0,0],7)
  add(f'cross-page-{kind}-{width}',[2,kind,width,8,0,1,0])
  add(f'truncated-{kind}-{width}',[2,kind,width,0,26,0,0],4)
 statuses={1:3,2:3,3:2,4:2,5:2,6:2,7:2,8:2,9:2,10:2,11:2,12:8,
 13:9,14:9,15:9,16:9,17:9,18:9,19:4,20:4,21:4,22:4,23:4,24:4,25:4,
 27:6,28:1,29:3,30:8,31:8,32:9,33:2,34:2,35:2,39:4,40:4,41:4,42:4,43:4,44:4,45:2,46:4,47:1,48:2}
 for control,status in statuses.items():
  mech=1 if control in (12,30,31) else 2
  add(f'refusal-{control}',[mech,2,16 if control==15 else 64,0,control,0,0],status)
 prefixes=[(2,16,8,1),(2,32,15,2),(2,64,0,1),(3,16,1,3),(3,32,14,2),(3,64,3,1),(4,64,15,2),(4,64,1,1)]
 for i,(kind,width,reg,prefix) in enumerate(prefixes):add(f'prefix-{i}',[2,kind,width,reg,0,0,prefix])
 # The historical case names stay fixed; classification follows exact bytes.
 # Memory /6 and /7 without a mandatory prefix encode VMX operations, not
 # malformed random instructions. F3 /7 memory remains invalid.
 edge_forms={
  (2,4):('invalid-lock-rdrand','f0480fc7f0',4),
  (2,5):('VMPTRLD_m64','480fc730',6),
  (2,6):('prefix-only-at-length-limit','66'*15,4),
  (3,4):('invalid-lock-rdseed','f0480fc7f8',4),
  (3,5):('VMPTRST_m64','480fc738',6),
  (3,6):('prefix-only-at-length-limit','66'*15,4),
  (4,4):('invalid-lock-rdpid','f0f30fc7f8',4),
  (4,5):('invalid-f3-0fc7-memory','f30fc738',4),
  (4,6):('prefix-only-at-length-limit','66'*15,4),
 }
 for kind in (2,3,4):
  for prefix in (4,5,6):
   instruction_class,encoding,status=edge_forms[kind,prefix]
   add(f'invalid-{kind}-{prefix}',[2,kind,64,0,0,0,prefix],status)
   cases[-1].update(instruction_class=instruction_class,encoding=encoding)
 add('actual-negative-gpr',[2,2,64,0,36,0,0],reject='post.gpr.12')
 add('actual-negative-fp',[2,2,64,0,37,0,0],reject='post.xstate')
 add('actual-nested-native-fetch',[1,2,64,0,38,0,0])
 return cases
