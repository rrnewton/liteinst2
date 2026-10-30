// Private cfg(test) owner and trace adapter. Existing oracle methods are unchanged.
use super::*;
use liteinst2::contracts::*;
use liteinst2::sync_core::SyncCore;
use liteinst2::trampoline::SavedExtendedStateLayout;
mod fixture { include!("routed_jmp_fixture.rs"); }
use fixture::*;
mod artifact { include!("routed_jmp_artifact.rs"); }

// Implemented only inside entry_router::imp's cfg(test) child. The counter
// coordinate is read from the stopped child, never dereferenced in the parent.
pub trait Router: Sized {
    fn prepare();
    fn verify();
    fn stage(routes: &[EntryRoute]) -> Self;
    fn counter_address(&self) -> u64;
    fn deactivate(&self);
    fn assert_active(&self);
}
struct Owner {
    oracle: NativeOracle,
    images: Vec<Mapping>,
    hooks: [Mapping; 2],
    journal: HookEventLog,
    original: Vec<u8>,
    published: Vec<u8>,
    immutable: Vec<(u64, Vec<u8>)>,
    proof: artifact::Proof,
    state: SavedExtendedStateLayout,
    generation: CodeIdentity,
}
impl Owner {
    fn new(row: Row, record: bool) -> Self {
        let mut oracle = NativeOracle::from_code_mapping(&[], Mapping::exact_page(SOURCE));
        let original = source_page(row);
        oracle.code.initialize(0, &original);
        oracle.original_code = original.clone();
        assert_eq!(oracle.return_pc(), TERMINAL);
        let images = IMAGE_PAGES.iter().map(|&address| Mapping::exact_page(address)).collect::<Vec<_>>();
        let hooks = [Mapping::exact_page(NULL_HOOK), Mapping::exact_page(RECORD_HOOK)];
        let journal = HookEventLog { memory: Mapping::exact_page(JOURNAL), capacity: 6 };
        journal.memory.initialize(0, &vec![0; PAGE]);
        let state = SavedExtendedStateLayout::detect().unwrap();
        let hook = if record { RECORD_HOOK } else { NULL_HOOK };
        let proof = artifact::produce(hook, state);
        artifact::controls(&proof);
        let mut immutable = Vec::new();
        for (mapping, image) in images.iter().zip(&proof.images) {
            let mut page = vec![0xcc; PAGE];
            let off = (image.address - mapping.address()) as usize;
            page[off..off + image.bytes.len()].copy_from_slice(&image.bytes);
            mapping.initialize(0, &page); mapping.protect(libc::PROT_READ | libc::PROT_EXEC);
            immutable.push((mapping.address(), page));
        }
        for (mapping, bytes) in hooks.iter().zip([NULL_BYTES, RECORD_BYTES]) {
            let mut page = vec![0xcc; PAGE]; page[..bytes.len()].copy_from_slice(bytes);
            mapping.initialize(0, &page); mapping.protect(libc::PROT_READ | libc::PROT_EXEC);
            immutable.push((mapping.address(), page));
        }
        let mut published = original.clone();
        published[(B-SOURCE) as usize..(B-SOURCE) as usize+FUNCTION.len()].copy_from_slice(&proof.source);
        oracle.code.protect(libc::PROT_READ | libc::PROT_EXEC);
        Self { oracle, images, hooks, journal, original, published, immutable, proof, state, generation: identity() }
    }
    fn lease(&self, expected: &[u8], generation: CodeIdentity) {
        assert_eq!(self.generation, generation, "stale fixture generation");
        assert_eq!(generation, identity());
        assert_eq!(self.oracle.code.bytes(), expected, "stale complete source page");
        assert_eq!(self.images.len(), 3); assert_eq!(self.hooks.len(), 2);
        for (mapping, (address, expected)) in self.images.iter().chain(&self.hooks).zip(&self.immutable) {
            assert_eq!(mapping.address(), *address); assert_eq!(mapping.bytes(), expected);
        }
        artifact::check(&self.proof);
    }
    fn publish<R: Router>(&self, routes: &R, sync: &SyncCore) {
        // No subject child exists here. Fixed no-replace Mapping owners retain
        // every page; only this owner can start executors or saved-F resumes.
        self.lease(&self.original, identity()); R::verify(); routes.assert_active();
        self.oracle.code.protect(libc::PROT_READ | libc::PROT_WRITE);
        self.oracle.code.initialize(0, &self.published);
        self.oracle.code.protect(libc::PROT_READ | libc::PROT_EXEC);
        sync.synchronize().unwrap();
        self.lease(&self.published, identity()); R::verify(); routes.assert_active();
    }
    fn restore<R: Router>(&self, routes: &R, sync: &SyncCore) {
        // All installed children have been exactly reaped before this call.
        self.lease(&self.published, identity()); R::verify(); routes.assert_active();
        self.oracle.code.protect(libc::PROT_READ | libc::PROT_WRITE);
        self.oracle.code.initialize(0, &self.original);
        self.oracle.code.protect(libc::PROT_READ | libc::PROT_EXEC);
        sync.synchronize().unwrap();
        routes.deactivate();
        self.lease(&self.original, identity());
    }
    fn immutable(&self, child: &Tracee, installed: bool) {
        assert_eq!(child.memory(SOURCE, PAGE), *(if installed { &self.published } else { &self.original }));
        for (address, bytes) in &self.immutable { assert_eq!(child.memory(*address, PAGE), *bytes); }
    }
}
struct Budget { used: usize }
impl Budget {
    fn charge(&mut self, child: &Tracee, count: usize) {
        self.used = self.used.checked_add(count).unwrap();
        assert!(self.used <= MAX_STEPS, "native instruction budget exhausted");
        assert!(Instant::now() < child.deadline, "native wall budget exhausted");
    }
    fn step(&mut self, child: &Tracee) {
        self.charge(child, 1); child.step(&[]);
    }
}
fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_ne_bytes(bytes[offset..offset+8].try_into().unwrap())
}
fn counter(child: &Tracee, address: u64) -> u64 { word(&child.memory(address, 8), 0) }
fn trap(child: &Tracee, signal: i32) {
    let status = child.wait();
    assert!(libc::WIFSTOPPED(status), "owned tracee exited: {status:#x}");
    assert_eq!(libc::WSTOPSIG(status), signal);
}
fn deliver(child: &Tracee, budget: &mut Budget, route: EntryRoute, counter_address: u64, before: u64) {
    assert_eq!(child.registers().rip, route.original);
    assert_eq!(counter(child,counter_address), before);
    budget.charge(child, 1);
    child.request(libc::PTRACE_SINGLESTEP, 0, 0); trap(child, libc::SIGILL);
    assert_eq!(child.registers().rip, route.original);
    // SAFETY: initialized native output for this stopped tracee's synchronous #UD.
    let mut info: libc::siginfo_t = unsafe { core::mem::zeroed() };
    child.request(libc::PTRACE_GETSIGINFO, 0, (&raw mut info) as usize);
    assert_eq!((info.si_signo, info.si_code), (libc::SIGILL, 2));
    assert_eq!(unsafe { info.si_addr() } as usize as u64, route.original);
    budget.charge(child, 1);
    child.request(libc::PTRACE_SINGLESTEP, 0, libc::SIGILL as usize); trap(child, libc::SIGTRAP);
    // Step the actual production handler and its actual libc restorer. No PC
    // setter, injected context, synthetic delivery, or inferred receipt exists.
    loop {
        let registers = child.registers();
        if registers.rax == libc::SYS_rt_sigreturn as u64 && child.memory(registers.rip, 2) == [0x0f,0x05] {
            child.request(libc::PTRACE_SETOPTIONS, 0, libc::PTRACE_O_TRACESYSGOOD as usize);
            budget.charge(child, 1);
            child.request(libc::PTRACE_SYSCALL, 0, 0); trap(child, libc::SIGTRAP | 0x80);
            assert_eq!(child.registers().orig_rax, libc::SYS_rt_sigreturn as u64);
            child.request(libc::PTRACE_SYSCALL, 0, 0); trap(child, libc::SIGTRAP | 0x80);
            child.request(libc::PTRACE_SETOPTIONS, 0, 0);
            assert_eq!(child.registers().rip, route.generated);
            assert_eq!(counter(child,counter_address), before+1, "child handler receipt after this exact delivery");
            return;
        }
        assert_ne!(registers.rip, route.generated, "route destination without witnessed rt_sigreturn");
        budget.step(child);
    }
}
fn finish(child: &Tracee) {
    // SAFETY: exact still-owned traced child; Drop retains its existing 2s cleanup.
    assert_eq!(unsafe { libc::kill(child.pid, libc::SIGKILL) }, 0);
    let status=child.wait();
    assert!(libc::WIFSIGNALED(status) && libc::WTERMSIG(status)==libc::SIGKILL && child.reaped.get());
}
fn seed(owner: &Owner, row: Row, seed: u64) -> Baseline {
    // One unchanged auxiliary seed child; it stops at the caller without
    // executing it. Only the subsequent subject's sole initial seed is varied.
    let mut baseline=owner.oracle.original(&[CALLER],seed);
    baseline.initial.rsp=owner.oracle.initial_rsp+8;
    baseline.initial.rip=CALLER;
    baseline.initial.r13=row.r13;
    baseline.initial.eflags=(baseline.initial.eflags & !(1 | (1<<6))) | row.flags;
    assert_ne!(baseline.initial.rdi,baseline.initial.r12);
    baseline.points.clear(); baseline
}
fn start(owner: &Owner, row: Row, baseline: &Baseline, resume: Option<&SignalResume>) -> (Tracee, Budget) {
    let child=Tracee::fork();
    let mut budget=Budget { used: 0 };
    // Charge the fixed TRACEME/stop startup as well as every later resumed
    // instruction. The unchanged Tracee deadline also covers all trace work.
    budget.charge(&child,2);
    child.set_registers(&baseline.initial); child.set_xstate(&baseline.xstate);
    let got=child.registers();
    assert_eq!(got.rip,CALLER); assert_eq!(got.rsp,owner.oracle.initial_rsp+8);
    let mut expected=owner.oracle.snapshot_with_registers(&child,CALLER,baseline.initial);
    expected.xstate=canonical_xstate(&baseline.xstate);
    let actual=owner.oracle.snapshot_with_registers(&child,CALLER,got);
    assert_state(&expected,&actual);
    assert_eq!(child.memory(CALLER,5),row.caller);
    assert_eq!(got.rsp%16,0);
    budget.step(&child); // Hardware subject CALL, separately observed.
    assert_eq!(child.registers().rip,row.entry);
    assert_eq!(child.registers().rsp,owner.oracle.initial_rsp);
    assert_eq!(child.registers().rsp%16,8);
    assert_eq!(child.memory(owner.oracle.initial_rsp,8),TERMINAL.to_ne_bytes());
    if row.resume {
        assert_eq!(row.entry,F);
        // Exact unchanged seam has INT3, RET, MOV and rt_sigreturn. Conservatively
        // charge all six resume/syscall observation transitions, without masking.
        budget.charge(&child,6);
        resume.unwrap().resume(&owner.oracle,&child);
        assert_eq!(child.registers().rip,F);
    } else { assert!(resume.is_none()); }
    (child,budget)
}
fn events(log: &HookEventLog, child: &Tracee, expected: &[u64], record: bool) {
    let events: Vec<_> = if record { expected.iter().map(|&pc| HookEvent { probe_id:pc,logical_pc:pc }).collect() } else { vec![] };
    log.assert_events(child,&events);
}
fn original(owner: &Owner, row: Row, baseline: &mut Baseline, counter_address: u64, resume: Option<&SignalResume>) {
    let _log=owner.journal.activate();
    let (child,mut budget)=start(owner,row,baseline,resume);
    for (index,&pc) in row.visits.iter().enumerate() {
        assert_eq!(child.registers().rip,pc,"frozen original visit {}",row.name);
        owner.immutable(&child,false); events(&owner.journal,&child,&[],false);
        assert_eq!(counter(&child,counter_address),0);
        baseline.points.push(owner.oracle.snapshot(&child,pc,&owner.original));
        if index+1<row.visits.len() {
            budget.step(&child);
            if index==0 && row.entry==L { assert_eq!(child.registers().rip,if row.flags==0 { U } else { B },"first SUBJECT branch"); }
        }
    }
    terminal(owner,&child);
    state_controls(&baseline.points[0]); immutable_controls(owner,&child,false);
    journal_controls(owner,&child);
    finish(&child);
}
fn terminal(owner: &Owner, child: &Tracee) {
    assert_eq!(child.registers().rip,TERMINAL);
    assert_eq!(child.registers().rsp,owner.oracle.initial_rsp+8);
    assert_eq!(child.memory(owner.oracle.initial_rsp,8),TERMINAL.to_ne_bytes());
}
fn context(owner: &Owner, child: &Tracee, expected: &Snapshot, returned: u64) {
    let r=child.registers(); let e=&expected.registers;
    assert_eq!(r.rip,owner.proof.hook); assert_eq!(r.rsp%16,8);
    let reserve=owner.oracle.initial_rsp-128;
    assert!(r.rsp>=owner.oracle.stack.address()+PAGE as u64 && r.rsp+8<=reserve);
    assert_eq!(word(&child.memory(r.rsp,8),0),returned);
    assert!(r.rdi>=owner.oracle.stack.address()+PAGE as u64 && r.rdi+176<=reserve);
    let c=child.memory(r.rdi,176);
    let words=[expected.logical_pc,e.rsp,e.r15,e.r14,e.r13,e.r12,e.r11,e.r10,e.r9,e.r8,e.rdi,e.rsi,e.rbp,e.rbx,e.rdx,e.rcx,e.rax];
    for (i,&value) in words.iter().enumerate() { assert_eq!(word(&c,i*8),value); }
    assert_eq!(word(&c,136)&!DEBUGGER_FLAGS,e.eflags&!DEBUGGER_FLAGS);
    let address=word(&c,144); assert_eq!(address%64,0);
    assert_eq!((word(&c,152),word(&c,160),word(&c,168)),(owner.state.len(),owner.state.mask(),owner.state.format().raw()));
    assert!(address>=owner.oracle.stack.address()+PAGE as u64 && address+owner.state.len()<=r.rdi);
    let bytes=child.memory(address,owner.state.len() as usize);
    assert_eq!(canonical_xstate(&bytes[..owner.state.image_len() as usize]),expected.xstate);
}
fn patched(owner: &Owner, row: Row, baseline: &Baseline, counter_address: u64, resume: Option<&SignalResume>, installed: bool) -> Vec<u8> {
    let _log=owner.journal.activate();
    let (child,mut budget)=start(owner,row,baseline,resume);
    let mut boundaries:BTreeMap<u64,u64>=HEADS.iter().map(|&pc|(pc,pc)).collect();
    boundaries.insert(TERMINAL,TERMINAL);
    if installed {
        for image in &owner.proof.images {
            for &(logical,generated) in &image.bodies { boundaries.remove(&logical); assert!(boundaries.insert(generated,logical).is_none()); }
        }
    }
    let record=installed && owner.proof.hook==RECORD_HOOK;
    let mut index=0; let mut hooks=Vec::new(); let mut deliveries=Vec::new();
    let mut active_hook:Option<(u64,u64)>=None;
    let mut first_subject=None;
    loop {
        budget.charge(&child,0);
        let pc=child.registers().rip;
        owner.immutable(&child,installed);
        assert_eq!(counter(&child,counter_address),deliveries.len() as u64);
        if installed {
            if let Some(&route)=owner.proof.routes.iter().find(|r|r.original==pc) {
                assert_eq!(row.deliveries.get(deliveries.len()),Some(&pc));
                deliver(&child,&mut budget,route,counter_address,deliveries.len() as u64);
                deliveries.push(pc); continue;
            }
            if let Some(image)=owner.proof.images.iter().find(|image|artifact::call(image,owner.proof.hook)==pc) {
                assert!(active_hook.is_none());
                let expected=baseline.points.get(index).expect("extra callback after last subject boundary");
                assert_eq!(expected.logical_pc,image.pc);
                assert_eq!(row.hooks.get(hooks.len()),Some(&image.pc),"unexpected callback identity/order");
                let before_rsp=child.registers().rsp; assert_eq!(before_rsp%16,0);
                budget.step(&child); assert_eq!(child.registers().rip,owner.proof.hook);
                assert_eq!(child.registers().rsp,before_rsp-8);
                context(owner,&child,expected,pc+5);
                // Positive actual HookContext precedes PC-identity mutants for
                // each selected B/L/U callback in both null and record modes.
                for wrong_pc in [B,L,U,F].into_iter().filter(|&wrong|wrong!=expected.logical_pc) {
                    let bad=Snapshot { logical_pc:wrong_pc,registers:expected.registers,
                        xstate:expected.xstate.clone(),data:expected.data.clone(),
                        application_stack:expected.application_stack.clone() };
                    refused(||context(owner,&child,&bad,pc+5));
                }
                active_hook=Some((pc+5,before_rsp));
                hooks.push(image.pc);
                // The CALL has already reached and authenticated this helper
                // entry. Execute its first instruction before returning to the
                // general observer; any later unowned entry still fails below.
                budget.step(&child);
                continue;
            }
            if pc==owner.proof.hook+if record { 59 } else { 10 } {
                let (returned,rsp)=active_hook.take().expect("unowned helper RET");
                assert_eq!(child.memory(pc,1),[0xc3]);
                assert_eq!(word(&child.memory(child.registers().rsp,8),0),returned);
                budget.step(&child); assert_eq!(child.registers().rip,returned); assert_eq!(child.registers().rsp,rsp);
                continue;
            }
            assert_ne!(pc,owner.proof.hook,"helper entry without actual CALL");
        }
        if let Some(&logical)=boundaries.get(&pc) {
            assert!(active_hook.is_none());
            let expected=baseline.points.get(index).expect("extra subject boundary");
            assert_eq!(logical,expected.logical_pc,"ordered visits, including repeats");
            let actual=owner.oracle.snapshot(&child,logical,if installed { &owner.published } else { &owner.original });
            assert_state(expected,&actual); events(&owner.journal,&child,&hooks,record);
            index+=1;
            if logical==TERMINAL { break; }
            if index==1 { first_subject=Some(pc); }
        }
        if let Some(first)=first_subject.take() {
            assert_eq!(pc,first);
            budget.step(&child);
            if row.entry==L { assert_eq!(child.registers().rip,if row.flags==0 {
                // The original false edge is the adjacent generated return JMP;
                // its direct target U is already checked before publication.
                if installed { first+6 } else { U }
            } else { B },"first SUBJECT branch"); }
        } else { budget.step(&child); }
    }
    assert_eq!(index,baseline.points.len()); assert_eq!(index,row.visits.len());
    assert_eq!(hooks,if installed { row.hooks } else { &[] });
    assert_eq!(deliveries,if installed { row.deliveries } else { &[] });
    assert!(active_hook.is_none()); terminal(owner,&child);
    immutable_controls(owner,&child,installed);
    let journal=child.memory(JOURNAL,PAGE);
    finish(&child);
    journal
}
fn state_controls(s: &Snapshot) {
    assert_state(s,s);
    for kind in 0..8 {
        let mut bad=Snapshot { logical_pc:s.logical_pc,registers:s.registers,xstate:s.xstate.clone(),data:s.data.clone(),application_stack:s.application_stack.clone() };
        match kind {
            0=>bad.registers.rdi^=1, 1=>bad.registers.r12^=1, 2=>bad.registers.eflags^=1,
            3=>bad.logical_pc^=1, 4=>bad.xstate[0]^=1,
            5=>*bad.data.last_mut().unwrap()^=1,
            6=>*bad.application_stack.last_mut().unwrap()^=1,
            _=>bad.registers.orig_rax^=1,
        }
        refused(||assert_state(s,&bad));
    }
}
fn immutable_controls(owner:&Owner, child:&Tracee, installed:bool) {
    owner.immutable(child,installed);
    for (address,bytes) in std::iter::once((SOURCE,if installed { &owner.published } else { &owner.original })).chain(owner.immutable.iter().map(|(a,b)|(*a,b))) {
        for offset in [0,PAGE-1] {
            let mut bad=bytes.clone(); bad[offset]^=1;
            refused(||assert_eq!(child.memory(address,PAGE),bad));
        }
    }
}
fn journal_controls(owner:&Owner, child:&Tracee) {
    // Real captured empty page is the positive. Expected-event mutations invoke
    // the unchanged comparator; nonempty actual-page mutants are exercised in a
    // separate stopped child below, before any subject or admitted publication.
    owner.journal.assert_events(child,&[]);
    for pc in [F,L,U,B] {
        refused(||owner.journal.assert_events(child,&[HookEvent { probe_id:pc,logical_pc:pc }]));
    }
}
fn journal_page_controls(owner:&Owner, good:&[u8]) {
    let expected:Vec<_>=[L,B,L,B,L,U].iter().map(|&pc|HookEvent { probe_id:pc,logical_pc:pc }).collect();
    assert_eq!(good.len(),PAGE);
    // These exact bytes were captured only after the installed native two-loop
    // record trace passed the unchanged full-page event comparator.
    // Mutate private parent-owned fixture storage before fork; never write a
    // subject tracee or use a mutant as an expected native result.
    for kind in 0..10 {
        let mut bytes=good.to_vec();
        match kind {
            0=>{}, 1=>bytes[8]=1, 2=>bytes[PAGE-1]=1, 3=>bytes[0]=5,
            4=>bytes[0]=7, 5=>bytes[16..24].copy_from_slice(&F.to_ne_bytes()),
            6=>bytes[24..32].copy_from_slice(&U.to_ne_bytes()),
            7=>{ let first=bytes[16..32].to_vec(); let second=bytes[32..48].to_vec(); bytes[16..32].copy_from_slice(&second);bytes[32..48].copy_from_slice(&first); },
            8=>{ bytes.fill(0); bytes[16]=1; },
            _=>{ bytes.fill(0);bytes[0]=1;bytes[16..24].copy_from_slice(&F.to_ne_bytes());bytes[24..32].copy_from_slice(&F.to_ne_bytes()); },
        }
        owner.journal.memory.initialize(0,&bytes);
        let child=Tracee::fork();
        if kind==0 { owner.journal.assert_events(&child,&expected); }
        else { refused(||owner.journal.assert_events(&child,if kind>=8 { &[] } else { &expected })); }
        finish(&child);
    }
    owner.journal.memory.initialize(0,&vec![0;PAGE]);
}
pub fn run<R:Router>(index:usize) {
    let row=ROWS[index];
    assert_eq!(HEADS.len(),24); assert_eq!(FUNCTION.len(),142); assert_eq!(ROWS.len(),31);
    assert_eq!(ROWS.iter().map(|r|r.entry).collect::<BTreeSet<_>>(),HEADS.iter().copied().collect());
    for record in [false,true] { for seed_value in SEEDS {
        let owner=Owner::new(row,record);
        owner.lease(&owner.original,identity());
        let mut stale=identity();stale.generation+=1;refused(||owner.lease(&owner.original,stale));
        let mut wrong=owner.original.clone();wrong[(F-SOURCE)as usize]^=1;refused(||owner.lease(&wrong,identity()));
        let sync=SyncCore::prepare().unwrap();R::prepare();R::verify();
        let routes=R::stage(&owner.proof.routes);routes.assert_active();
        let counter_address=routes.counter_address();
        // SAFETY: only this exact isolated row owns SIGUSR1 and the subject maps.
        let resume=if row.resume { Some(unsafe { SignalResume::new() }) } else { None };
        let mut baseline=seed(&owner,row,seed_value);
        original(&owner,row,&mut baseline,counter_address,resume.as_ref());
        owner.publish::<R>(&routes,&sync);
        let journal=patched(&owner,row,&baseline,counter_address,resume.as_ref(),true);
        if index==10 && record && seed_value==SEEDS[0] { journal_page_controls(&owner,&journal); }
        owner.restore::<R>(&routes,&sync);
        patched(&owner,row,&baseline,counter_address,resume.as_ref(),false);
        if let Some(resume)=resume { assert_eq!(resume.completed_roundtrips(),3); }
    } }
}

pub fn inactive_or_unowned_f<R:Router>(inactive:bool) {
    let row=ROWS[5]; assert_eq!(row.entry,F);
    let owner=Owner::new(row,false);
    let baseline=seed(&owner,row,SEEDS[0]);
    let sync=SyncCore::prepare().unwrap();R::prepare();R::verify();
    let routes=R::stage(if inactive { &owner.proof.routes } else { &owner.proof.routes[..1] });
    if inactive {
        routes.deactivate();
        refused(||owner.publish::<R>(&routes,&sync));
        assert_eq!(owner.oracle.code.bytes(),owner.original);
    }
    // Deliberately unadmitted negative: publish the exact already-checked mixed
    // bytes with F absent/inactive. No positive receipt or fallback is produced.
    owner.lease(&owner.original,identity());
    owner.oracle.code.protect(libc::PROT_READ|libc::PROT_WRITE);
    owner.oracle.code.initialize(0,&owner.published);
    owner.oracle.code.protect(libc::PROT_READ|libc::PROT_EXEC);
    sync.synchronize().unwrap();
    let (child,mut budget)=start(&owner,row,&baseline,None);
    assert_eq!(child.registers().rip,F);
    budget.charge(&child,1);
    assert_eq!(child.synchronous_fault(),(libc::SIGILL,2,F));
    budget.charge(&child,1);
    child.request(libc::PTRACE_SINGLESTEP,0,libc::SIGILL as usize);
    loop {
        let status=child.wait();
        if libc::WIFSIGNALED(status) {
            assert_eq!(libc::WTERMSIG(status),libc::SIGILL);assert!(child.reaped.get());break;
        }
        assert!(libc::WIFSTOPPED(status));
        let signal=libc::WSTOPSIG(status);
        assert_eq!(counter(&child,routes.counter_address()),0,"unowned fault must not route");
        budget.charge(&child,1);
        if signal==libc::SIGILL {
            // The unchanged real handler resets SIG_DFL and raises SIGILL.
            // Forward that signal too; an observer rejection is not success.
            child.request(libc::PTRACE_SINGLESTEP,0,libc::SIGILL as usize);
        } else {
            assert_eq!(signal,libc::SIGTRAP);
            child.request(libc::PTRACE_SINGLESTEP,0,0);
        }
    }
    routes.deactivate();
    // The subject is exactly reaped; private source restoration is exclusive.
    owner.oracle.code.protect(libc::PROT_READ|libc::PROT_WRITE);
    owner.oracle.code.initialize(0,&owner.original);
    owner.oracle.code.protect(libc::PROT_READ|libc::PROT_EXEC);
    sync.synchronize().unwrap();owner.lease(&owner.original,identity());
}

pub fn gate_fixture(gates:impl FnOnce(&[EntryRoute])) {
    let owner=Owner::new(ROWS[5],false);
    owner.lease(&owner.original,identity());
    gates(&owner.proof.routes);
    owner.lease(&owner.original,identity());
}
