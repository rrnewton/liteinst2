"""Exact static source continuity for anonymous reset and RX/TLS successors.

This only reconstructs explicitly pinned historical source bytes for a caller's
unchanged comparison. Builds, policy binding, compiler inputs and receipts keep
the actual installed bytes. No historical result or qualification is reused.
"""
from page_selected_maps_sources import byte_fact, inverse, need

# Current endpoints are reviewed whole sources. Existing reset prior/target
# facts remain literal. New RX/TLS rows restore only the exact pre-install source;
# they do not add older targets or change any caller expected dictionary.
SOURCES = {
  "evaluation/inprocess/direct_frontier_loop_helpers.py": {
    "current": {
      "bytes": 42994,
      "sha256": "4c60916275f6ca6f2a22291f4f8ea1ff6243d65dae26d0c6075287f228368b40"
    },
    "inverse": [
      [
        28,
        30,
        "def reader_support(builder,private,pin,binary,run,r):\n"
      ],
      [
        31,
        32,
        "    reader=load('persistent_direct_frontier_app_read',FIXTURE/'read.py',pin)\n"
      ]
    ],
    "prior": {
      "bytes": 42898,
      "sha256": "660a6fe4ba2f83a164082369c4af1e1d0a5f1ddbc2bc9fbe581343fbdc5f586c"
    },
    "targets": {}
  },
  "evaluation/inprocess/page_cost_compare.py": {
    "current": {
      "bytes": 32774,
      "sha256": "25d7936d74a290217c9aee65d0a93b0c5eece40a9905a750135c1377351584ca"
    },
    "inverse": [
      [
        282,
        289,
        ""
      ],
      [
        305,
        306,
        "                parsed,summary=cost_reports.check(out,err,row['pid'],row['exit'],row['stdout_provenance_before'],\n"
      ],
      [
        308,
        309,
        "                r['reader_controls'][name]=cost_reports.supplied_controls(out,err,row['pid'],row['exit'],\n"
      ],
      [
        323,
        324,
        ""
      ]
    ],
    "prior": {
      "bytes": 32256,
      "sha256": "ac8ea0af83b8b1c7a6d1571fdc6df2674dc39f504f85fd2320c4c6e807dd29fc"
    },
    "targets": {}
  },
  "tools/page-entry/selected/maps_phase.inc": {
    "current": {
      "bytes": 8318,
      "sha256": "f0be07f30fbf0297c43845cf0322d5722d319344a27a863ba5d13fd7b7ad238b"
    },
    "inverse": [
      [
        85,
        88,
        ""
      ]
    ],
    "prior": {
      "bytes": 8224,
      "sha256": "98babb5716bc5fb59586b3826a534e2836def176556d9c6ac5c2906eca50239f"
    },
    "targets": {}
  },
  "tools/page-entry/selected/maps_view.h": {
    "current": {
      "bytes": 1474,
      "sha256": "cafc0e86b1779b4cb592f11f4db2d108de75252724e7f2cf80f464dd3d43853b"
    },
    "inverse": [
      [
        23,
        28,
        ""
      ]
    ],
    "prior": {
      "bytes": 1109,
      "sha256": "922759a82e755b26423b5933269c5e9bc7614e4e884d873f868e41d328ed3eba"
    },
    "targets": {}
  },
  "tools/page-entry/selected/maps_view.inc": {
    "current": {
      "bytes": 27104,
      "sha256": "d9048f0603e9bc281c81076ba20efba26c140f42032a53a9fc9d3a94c94f5dde"
    },
    "inverse": [
      [
        1,
        4,
        "   unchanged. Only an actual successful gateway mprotect updates permissions.\n   Other mapping changes invalidate BEFORE execution, including partial errors.\n"
      ],
      [
        216,
        219,
        ""
      ],
      [
        317,
        371,
        ""
      ]
    ],
    "prior": {
      "bytes": 23681,
      "sha256": "b52bc63fcf250d7df52d4c6e65098e131dabf8e4114978370a7ad133141ebe68"
    },
    "targets": {
      "25404fa1b73de3e815e20d904bbef500ec9c06f7093b3f17bbe05c4e7c37edfa": {
        "fact": {
          "bytes": 23459,
          "sha256": "25404fa1b73de3e815e20d904bbef500ec9c06f7093b3f17bbe05c4e7c37edfa"
        },
        "inverse": [
          [
            33,
            36,
            ""
          ],
          [
            148,
            151,
            ""
          ],
          [
            487,
            490,
            ""
          ]
        ]
      }
    }
  },
  "tools/page-entry/selected/sealed_generation.inc": {
    "current": {
      "bytes": 13954,
      "sha256": "104c70649366411e64b2f397ecf7e0db8ea840db2168d7a3a0bf89db8c572740"
    },
    "inverse": [
      [
        147,
        158,
        ""
      ],
      [
        176,
        179,
        ""
      ],
      [
        181,
        182,
        ""
      ],
      [
        186,
        189,
        ""
      ],
      [
        191,
        192,
        ""
      ]
    ],
    "prior": {
      "bytes": 13215,
      "sha256": "ec94e8d1dbbaf4d56eb9c436dd630c54801ae00ac4220c97e84ab10ffed2c5dc"
    },
    "targets": {}
  },
  "tools/page-entry/selected/tests/persistent_direct_frontier_app/main.c": {
    "current": {
      "bytes": 19543,
      "sha256": "b5641c7540f862d38c36b4500bec0a5d8fa7bfd3511f20f3ede8c95f2db4f356"
    },
    "inverse": [
      [
        15,
        18,
        ""
      ],
      [
        50,
        53,
        ""
      ],
      [
        54,
        58,
        ""
      ],
      [
        59,
        60,
        ""
      ],
      [
        101,
        105,
        ""
      ],
      [
        112,
        113,
        ""
      ],
      [
        119,
        122,
        ""
      ],
      [
        123,
        124,
        ""
      ],
      [
        182,
        185,
        ""
      ],
      [
        186,
        187,
        ""
      ],
      [
        211,
        214,
        ""
      ],
      [
        215,
        216,
        ""
      ],
      [
        262,
        265,
        ""
      ],
      [
        266,
        267,
        ""
      ],
      [
        296,
        299,
        ""
      ],
      [
        300,
        301,
        ""
      ]
    ],
    "prior": {
      "bytes": 18214,
      "sha256": "0a6fb0a2974a0557733079f8e3b0b7e9922ea846c4b2798dceaf855df8c72766"
    },
    "targets": {}
  },
  "tools/page-entry/selected/tests/persistent_direct_frontier_app/read.py": {
    "current": {
      "bytes": 36830,
      "sha256": "ba86eca297742d95498b8f535276daccc278e67336f84fcb5906e06cc9bb6581"
    },
    "inverse": [
      [
        13,
        22,
        ""
      ],
      [
        161,
        162,
        "def reference_frame(data, prefix, layout, kind, steps, attempt):\n"
      ],
      [
        177,
        178,
        "    g = q(uc, 40, 23); pc = frame_pc(prefix,kind)\n"
      ],
      [
        183,
        184,
        "    expected = frame_state(prefix,kind)\n"
      ],
      [
        185,
        186,
        "    expected_flags=trace_model(prefix)[steps][2] | (RF if kind==0 else TF)\n"
      ],
      [
        210,
        211,
        "def fixture(mode,image):\n"
      ],
      [
        214,
        216,
        "    seed[8]=2;seed[9]=1;seed[10]=1\n"
      ],
      [
        227,
        228,
        "def trace_model(prefix):\n"
      ],
      [
        233,
        234,
        "    for _ in range(41):\n"
      ],
      [
        261,
        265,
        "def frame_pc(prefix,kind):\n    need(type(kind)is int and 0<=kind<len(STEPS),'one of12 explicitly retained native boundaries')\n    return trace_model(prefix)[STEPS[kind]][0]\n"
      ],
      [
        266,
        267,
        "def frame_state(prefix,kind):return trace_model(prefix)[STEPS[kind]][1]\n"
      ],
      [
        268,
        269,
        "def state(seed,data,mode):\n"
      ],
      [
        270,
        271,
        "    out=list(seed);out[0]+=9;out[1]=0;out[8]=1;out[10]=U64-1;return tuple(out)\n"
      ],
      [
        276,
        277,
        "def _prefix(data,mode,native,image,pid,cpu,seed_reference):\n"
      ],
      [
        279,
        280,
        ""
      ],
      [
        285,
        286,
        "    need(h[:9]==(MAGIC,10,PREFIX,SUFFIX,mode,int(native),pid,pid,cpu)and h[9]<=0xffffffff and h[10:14]==(head,image['page'],DATA,STACK),'exact source/process/entry')\n"
      ],
      [
        287,
        288,
        "    need(h[30:]==(1,224,DATA+8192 if mode==1 else 0,8 if mode==1 else 0,frontier,predecessor,TRACES[mode],OBS,12,40,image['page']+0x2400,image['page']+PAGE,16384,RSEQ,0x53053053,image['page']+0x215,image['page']+0x3ffa,image['page']+0x241b),'exact cyclic fixture and reserved header')\n"
      ],
      [
        296,
        297,
        "    expected,want_data,want_stack=fixture(mode,image)\n"
      ],
      [
        302,
        303,
        "def read(data,mode,native,exit_status,image,pid,cpu,seed_reference):\n"
      ],
      [
        306,
        308,
        "    r=_prefix(data[:PREFIX],mode,native,image,pid,cpu,seed_reference)\n"
      ],
      [
        310,
        311,
        "    need(end==(MAGIC^1,10,mode,int(native),0,1,1,12 if native else 0,TRACES[mode]if native else 0,int(mode==1),2,1,0,0,0,0),'complete cleanup and collection-before-registration chronology')\n"
      ],
      [
        319,
        320,
        "    need(h==(1,0,12 if native else 0,TRACES[mode]if native else 0,int(mode==1),int(native),0,0,image['symbols']['region_app_capture_high'],0,0,0,0,0,0,0),'whole invocation header')\n"
      ],
      [
        321,
        322,
        "    need(after[0]==state(r['seed'][0],r['data'],mode)and after[1]==0x246,'all defined loop GPR and flag results')\n"
      ],
      [
        329,
        331,
        "            steps=STEPS[i]\n            frames.append(reference_frame(frame,r,image,kind,steps,0))\n"
      ],
      [
        340,
        341,
        "def controls(data,mode,native,exit_status,image,pid,cpu,seed_reference):\n"
      ],
      [
        343,
        344,
        "    read(data,mode,native,exit_status,image,pid,cpu,seed_reference)\n"
      ],
      [
        373,
        374,
        "        try:read(bytes(mutant),mode,native,exit_status,image,pid,cpu,seed_reference)\n"
      ],
      [
        377,
        387,
        ""
      ],
      [
        393,
        394,
        "    need(native['header'][8:19]==gated['header'][8:19]and native['hardware']==gated['hardware']and all(native[k]==gated[k]for k in('seed','source','stack','data','rsp','predecessor')),'whole same-source/CPU/seed pair inputs')\n    need(len(native['observations'])==len(gated['observations'])==1,'actual complete application observations')\n"
      ],
      [
        426,
        427,
        "    actual=gated['observations'][0]\n    need(all(reference[k]==actual[k]for k in('before','after','live','data','stack'))and gated['effects']==native['effects']and gated['suffix']is not None,'whole actual application state and later registration lifecycle')\n"
      ]
    ],
    "prior": {
      "bytes": 35492,
      "sha256": "273cd7c05858c889bef229d2f32439ee794e8f3107bf04d8e5d21457f2f12b71"
    },
    "targets": {}
  },
  "tools/page-entry/selected/tf_chain.h": {
    "current": {
      "bytes": 7628,
      "sha256": "1987d95c4f8f333c0e91705109a87f688043b499e780283c5bcaf813fd25eee9"
    },
    "inverse": [
      [
        132,
        143,
        ""
      ]
    ],
    "prior": {
      "bytes": 6938,
      "sha256": "47dc40d0761f757272484cd0aaf7608ee6ef3447c3ce80c378232fdbd9cd85e2"
    },
    "targets": {}
  }
}


def historical(relative, want, observed, raw):
    row = SOURCES.get(relative)
    if row is None:
        return dict(observed)  # Original caller comparison still rejects drift.
    need(byte_fact(raw) == row['current'],
         'one exact anonymous-reset source successor; no mixed versions')
    prior = inverse(raw, row['inverse'], row['prior'])
    if want == row['prior']:
        original = prior
    else:
        target = row['targets'].get(want['sha256'])
        need(target is not None and target['fact'] == want,
             'one unchanged historical anonymous-reset source target')
        original = inverse(prior, target['inverse'], want)
    return dict(observed, **byte_fact(original))
