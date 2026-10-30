#!/usr/bin/env python3
"""Pure report from seven immutable public receipts and two exact route projections."""
from pathlib import Path
import argparse,collections,csv,hashlib,json,statistics
R=Path(__file__).resolve().parents[2]
ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--results',type=Path,default=R/'evaluation/inprocess/results')
ap.add_argument('--routes-results',type=Path);args=ap.parse_args();P=args.results;RP=args.routes_results or P
STEMS=['20261029T224041.992538Z-page-cost-compare-c97096fad229', '20261029T231437.366556Z-page-cost-profile-ls-60a4415c54fa', '20261029T231527.423636Z-page-cost-profile-true-60a4415c54fa', '20261029T231615.636586Z-page-cost-counters-3675540b8ada', '20261029T234233.369460Z-page-cost-compare-c14f3078a1b5', '20261029T234819.052033Z-page-cost-profile-ls-c14f3078a1b5', '20261029T234913.280920Z-page-cost-profile-true-c14f3078a1b5']
PINS={'20261029T224041.992538Z-page-cost-compare-c97096fad229': '2bc3395779b692c89c412ed6e1a1b875b45b68bba4dde3082d836e485416a1b0', '20261029T231437.366556Z-page-cost-profile-ls-60a4415c54fa': '5f91a905dd0ff0fe856cadbdaafa2a42dfbb6a483b1f16883db6a1d27b22a2f1', '20261029T231527.423636Z-page-cost-profile-true-60a4415c54fa': 'b8470494ea6e344955c771a047f048b63a1850f97db966db65952892d5a18202', '20261029T231615.636586Z-page-cost-counters-3675540b8ada': '4ab36a3f5c6642b3a0f24d11b323c5750df9980b113f997f11b5092c9dd4bb0c', '20261029T234233.369460Z-page-cost-compare-c14f3078a1b5': '99ff000c346a28bd3d23e1b1efd8c22fb08279f6a0f526a7ca356f0e40e54782', '20261029T234819.052033Z-page-cost-profile-ls-c14f3078a1b5': 'a99c0e7deca45bdae21cf3acee98529623b7c4f6fb12a888626861525b88de6d', '20261029T234913.280920Z-page-cost-profile-true-c14f3078a1b5': 'cc879705abaa18b7ca0d3cbdd5afff1e4eeff86a1420cf69cf1056083bb157c4'}
H=lambda b:hashlib.sha256(b).hexdigest()
def read(stem):
 b=(P/(stem+'.json')).read_bytes();assert H(b)==PINS[stem];v=json.loads(b)
 assert v['status']=='passed'and v['source_unchanged']and v['cleanup_complete']and v['final_error_count']==0
 return v
def rows(stem,fact,kind=''):
 b=(P/(stem+kind+'.csv')).read_bytes();assert(len(b),H(b))==(fact['bytes'],fact['sha256'])
 return list(csv.DictReader(b.decode().splitlines()))
b,ls,tr,c=map(read,STEMS[:4]);post,postls,posttr=map(read,STEMS[4:]);profiles=[ls,tr,postls,posttr];cats=[]
ROUTE_PINS={'20261029T224041.992538Z-page-cost-compare-c97096fad229-routes':'ca75c755700291b908c0fa2771db0173157899f466f16b316459d36320a846fe','20261029T234233.369460Z-page-cost-compare-c14f3078a1b5-routes':'8405bbdb3deaac7538cd51250f0dad69d17d04f3c04b999029f09be1b2b64adc'}
route_data=[]
for stem,v in zip((STEMS[0],STEMS[4]),(b,post)):
 raw=(RP/(stem+'-routes.json')).read_bytes();assert H(raw)==ROUTE_PINS[stem+'-routes'];d=json.loads(raw)
 assert d['source']==v['source']and d['private_receipt']==v['private_receipt']and len(d['rows'])==20 and d['closed_population']==dict(subjects=60,gated_terminals=20,commands=96,supplied_refusals=2780)
 raw=(RP/d['csv']['file']).read_bytes();assert (len(raw),H(raw))==(d['csv']['bytes'],d['csv']['sha256'])
 assert list(csv.reader(raw.decode().splitlines()))==[d['columns']]+[[str(x)for x in row]for row in d['rows']]
 route_data.append([dict(zip(d['columns'],row))for row in d['rows']])
for stem,v in zip([STEMS[i]for i in(1,2,5,6)],profiles):
 n=collections.Counter();p=collections.Counter();raw=rows(stem,v['csv']);kernel=rows(stem,v['kernel_csv'],'-kernel')
 for x in raw:
  if x['cpumode']=='1':continue
  s=x['symbol'];reason=x['reason']
  if x['in_exec_window']!='True':k='outside exec window'
  elif reason!='authenticated_bridge_symbol':k='other user mapping / unknown'
  elif s in('li2_repeat_custody_quiet','li2_repeat_lease_closed'):k='cold-owner closure functions'
  elif s in('read_maps_checked.part.0','number_checked.constprop.0'):k='user maps parse'
  elif s in('frame','np_life_copy','lease_frame_copy','chain_frame_equal','np_capture'):k='state copy/compare'
  elif s in('memcpy','memset'):k='shared memcpy/memset, caller unknown'
  elif s in('handler','li2_tf_trace','li2_tf_chain_trace','li2_step_trace','li2_step_begin'):k='named trap/step leaves'
  elif s.startswith('li2_run_'):k='run-cache owner leaves'
  elif s=='li2_native_policy':k='native all-offset policy'
  elif 'iced_x86'in s or 'decoder'in s:k='decoder/classifier/footprint leaves'
  else:k='other authenticated bridge leaves'
  n[k]+=int(x['samples']);p[k]+=int(x['sampled_period_total'])
 for x in kernel:
  s=x['aliases']
  if x['kind']!='core_text_symbol_interval':
   assert x['kind']=='outside_core_text'and x['sampled_period_total']==''and v['kernel']['unknown_reasons']=={'outside_core_text':int(x['samples'])}
   n['unknown kernel outside core']+=int(x['samples']);p['unknown kernel outside core']+=v['kernel']['unknown_sampled_period_total'];continue
  elif all(y.startswith('perf_')for y in s.split('|')):k='perf-named kernel observer'
  elif s in('proc_get_vma','show_vma_header_prefix','get_vma_name')or s.startswith('show_map_vma.'):k='named proc-VMA kernel leaves'
  elif s in('seq_path','seq_put_hex_ll'):k='generic seq formatting, caller unknown'
  elif s=='lock_next_vma':k='VMA lock, caller unknown'
  elif s=='membarrier_private_expedited':k='kernel membarrier'
  elif s.startswith('__htab_map_lookup_elem'):k='BPF hash lookup, caller unknown'
  else:k='other known core kernel leaves'
  n[k]+=int(x['samples']);p[k]+=int(x['sampled_period_total'])
 assert sum(n.values())==v['sampling']['samples']and sum(p.values())==v['sampling']['sampled_period_total'];cats.append((n,p))
base=rows(STEMS[0],b['csv']);assert len(base)==60 and all(x['status']=='passed'and x['exit']=='0'for x in base)
assert collections.Counter((x['workload'],x['lane'])for x in base)==collections.Counter({(k,l):10 for k in('ls','true')for l in('native','gated','dynamorio')})
assert len(rows(STEMS[3],c['csv']))==len(c['cases'])==12 and all(x['status']=='passed'for x in c['cases'])
postrows=rows(STEMS[4],post['csv']);assert len(postrows)==60 and all(x['status']=='passed'and x['exit']=='0'for x in postrows)
assert [(x['ordinal'],x['workload'],x['repeat'],x['lane'])for x in postrows]==[(x['ordinal'],x['workload'],x['repeat'],x['lane'])for x in base]
assert all(b[k]==post[k]for k in('archive','program_inputs','sdk','dynamorio_client','bounds','recipes','order'))
assert b['commands']==post['commands']==96 and b['reader_controls']==post['reader_controls']
lines=['Measured release cost before/after bounded zero-scan unroll','',
 'Both cohorts retain all 60 fixed launches/96 commands; separate 99 Hz profiles retain every sample. No resampling/outlier removal.','',
 '| Workload/lane | before median / IQR ms | after median / IQR ms | after/before |','|---|---:|---:|---:|']
for kind in('ls','true'):
 for lane in('native','gated','dynamorio'):
  a,z=(v['statistics'][kind][lane]for v in(b,post));lines.append(f"|{kind}/{lane}|{a['median_ns']/1e6:.8f} / {a['iqr_ns']/1e6:.8f}|{z['median_ns']/1e6:.8f} / {z['iqr_ns']/1e6:.8f}|{z['median_ns']/a['median_ns']:.6f}|")
lines+=['',
 'Whole intervals run from pre-Popen to reap, including gated Python/namespace work; offline builds excluded. /bin/ls -d . and /bin/true are fresh processes, not steady throughput/full first-touch. CPU 34→6 and changed windows prevent isolated causality. Slow initial DR-ls/gated-true and all raw CSV rows remain.',
 'Inputs/archive/tools/release recipe/SDK/empty DR client match. The historical-source audit finds six changed compiler inputs: four absent-macro diagnostic blocks peel byte-exact to before; two bounded 32-byte zero loops retain old word/tails. Driver, terminal reader and launch sources match. Public numbers alone do not prove source identity.',
 '', '| Disjoint sampled leaf category | ls before→after count/percent | true before→after count/percent |','|---|---:|---:|']
keys=sorted(set().union(*(set(n)for n,p in cats)),key=lambda k:-max(cats[i][1][k]/profiles[i]['sampling']['sampled_period_total']for i in range(4)))
for k in keys:
 cells=[]
 for i in(0,1):cells.append('→'.join(f"{cats[j][0][k]}/{100*cats[j][1][k]/profiles[j]['sampling']['sampled_period_total']:.2f}%"for j in(i,i+2)))
 lines.append('|'+k+'|'+'|'.join(cells)+'|')
lines+=['','All samples / sampled period ns: ls '+ '→'.join(str(v['sampling']['samples'])+'/'+str(v['sampling']['sampled_period_total'])for v in(ls,postls))+'; true '+ '→'.join(str(v['sampling']['samples'])+'/'+str(v['sampling']['sampled_period_total'])for v in(tr,posttr))+'.',
 'Kernel share ls '+ '→'.join(f"{100*v['kernel']['kernel_sampled_period_total']/v['sampling']['sampled_period_total']:.3f}%"for v in(ls,postls))+'; true '+ '→'.join(f"{100*v['kernel']['kernel_sampled_period_total']/v['sampling']['sampled_period_total']:.3f}%"for v in(tr,posttr))+'. Unknowns and perf observer costs remain separate; generic seq/VMA/BPF/copy leaves have no caller attribution. Core kallsyms intervals may include padding. No ptrace-stop count was measured; no zero claim.',
 'Top 3 known product groups before were cold-owner scans (~25%), user maps parse (6.13% ls), state copy/compare (5.03% ls). Public CSVs show closure-function periods ls 6141414080→2404040380ns and true 2303030280→1151515140ns. ELF/PC audit confirms 237 ls/113 true samples in four-qword OR loops with stride 32 across the same 269440 bytes, plus one cold tail/return each. This proves the unroll ran, not an isolated wall-time effect.',
 'Before profiles used CPU 1; after ls 15 / true 3. True profiled whole interval increased 9.333→10.243s even while sampled period fell. Whole-time decomposition or uniform profile speedup would be unjustified.',
 '', '| Terminal routes before→after (10 gated runs each) | ls | true |','|---|---:|---:|']
routes=[('native attempts',lambda t:t['native']['attempts']),('native admitted pages',lambda t:t['native']['admissions']),('native policy blocked',lambda t:t['native']['blocked']),('pair NX events',lambda t:t['native_pair']['counts'][0]),('pair epochs',lambda t:t['native_pair']['counts'][1]),('pair extensions',lambda t:t['native_pair']['counts'][2]),('pair refaults',lambda t:t['native_pair']['counts'][8])]
for label,f in routes:
 cells=[]
 for kind in('ls','true'):
  intervals=[]
  for baseline in(b,post):
   values=[f(t)for name,t in baseline['terminals'].items()if name.startswith(kind+'-')];assert len(values)==10
   intervals.append(str(min(values))if min(values)==max(values)else f'{min(values)}–{max(values)}')
  cells.append('→'.join(intervals))
 lines.append('|'+label+'|'+'|'.join(cells)+'|')
extra=[('loader NX','loader.nx_faults'),('loader selected_steps','loader.selected_steps'),('generic TF attempts/steps; chain steps','loader.generic_tf_steps'),('chain NX entries','chain.nx_entries'),('chain TRACE entries','chain.trace_entries'),('chain retained transfers','chain.lease_transfers'),('TRACE-run candidates','trace_run.candidates'),('TRACE-run preflight misses','trace_run.preflight_misses'),('TRACE-run attempts/entries/completions','trace_run.completed'),('TRACE-run plan/full misses','trace_run.plan_misses')]
for data in route_data:
 assert all(x['loader.generic_tf_attempts']==x['loader.generic_tf_steps']==x['chain.steps']and x['trace_run.attempts']==x['trace_run.entries']==x['trace_run.completed']and x['trace_run.plan_misses']==x['trace_run.full_misses']==0 for x in data)
for label,field in extra:
 cells=[]
 for kind in('ls','true'):
  intervals=[]
  for data in route_data:
   values=[x[field]for x in data if x['workload']==kind];assert len(values)==10
   intervals.append(str(min(values))if min(values)==max(values)else f'{min(values)}–{max(values)}')
  cells.append('→'.join(intervals))
 lines.append('|'+label+'|'+'|'.join(cells)+'|')
lines+=['','Min–max across 10 gated runs; all 40 raw route rows are in the additive CSVs. Counters overlap, so these are not disjoint instruction/trap totals.','', '| Counter diagnostic (3 observed runs each) | ls | true |','|---|---:|---:|']
observed={k:[x for x in c['cases']if x['workload']==k and x['lane']=='counters']for k in('ls','true')}
for label,f in [('admissions',lambda x:x['cost']['admission'][4]),('admission sum ns',lambda x:x['cost']['admission'][5]),('mean admission ns (sum/count)',lambda x:format(x['cost']['admission'][5]/x['cost']['admission'][4],'.3f')),('fresh maps reads',lambda x:x['cost']['maps'][0]),('maps reuse',lambda x:x['cost']['maps'][2]),('handler phases',lambda x:x['cost']['maps'][4])]:lines.append('|'+label+'|'+'|'.join(';'.join(str(f(x))for x in observed[k])for k in('ls','true'))+'|')
ratios=[statistics.median(x['cost']['admission'][5]/x['process_ns']for x in observed[k])for k in('ls','true')]
lines+=['',f'Existing successful admission intervals are {100*ratios[0]:.3f}%/{100*ratios[1]:.3f}% of process intervals (median), excluding ingress/blocked attempts/closure and overlapping sampled categories. Maps precede report writes. Original + 27 diagnostic controls passed. Counter/unobserved median ratios 0.989786/0.993844 (3 each) do not prove negative overhead; layout changes some route counts.',
 'Next unqualified designs: reuse maps snapshots across proved nonmutating ownership phases with all source/alias/session and raw/event invalidations; batch same-state transitions per proved epoch while preserving full GPR/flags/FP/source/progress checks. No stale-cache permission, lost check or broader authority. Before-sample conditional 2x Amdahl for zero/maps/copy was 1.142x/1.032x/1.026x ls; these are not measured causal gains.','', 'Provenance / exact reproduction','']
lines+=['Read each JSON’s reproduce field for exact argv and csv field for hashes. Route JSONs pin their private receipt/projector; no new execution.','']
for stem,v in zip(STEMS,[b,ls,tr,c,post,postls,posttr]):lines+=['- '+stem+'.json '+PINS[stem]]
for stem,sha in ROUTE_PINS.items():lines+=['- '+stem+'.json '+sha]
lines+=['',f"{b['hardware']['model name']}; family {b['hardware']['cpu family']}/model {b['hardware']['model']}, microcode {b['hardware']['microcode']}, kernel {b['hardware']['kernel_version']}. Baseline CPUs 34/6; counter 15. No cache-cold claim.",
 'Bounds unchanged: native/gated 30 CPU seconds/512MiB address space/16MiB file size/60wall; profiler 30 CPU/1GiB/128MiB file size/80wall. DR 11.91.0 empty-client reserves 16 GiB address space. File size is not capture volume. All failure precursors stay failed, including the separate rseq pre-execution failure; no gate/comparator/cap/population is relaxed.']
text='\n'.join(lines)+'\n';assert len(text.encode())<=8192 and '/home/'not in text;print(text,end='')
