"""Exact source continuity for trusted anonymous reset projection.

This only reconstructs explicitly pinned historical source bytes for a caller's
unchanged comparison. Builds, policy binding, compiler inputs and receipts keep
the actual installed bytes. No historical result or qualification is reused.
"""
from page_selected_maps_sources import byte_fact, inverse, need

# Current endpoints are the reviewed anonymous reset; prior endpoints are the
# complete pre-reset files. The one older maps target removes only the three
# pre-existing resident-capture insertions, as its old owner manifest requires.
SOURCES = {
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
      "bytes": 27010,
      "sha256": "d9e5381a362dc5e14310809e8ce3d9d228ef5963ed99b891d67845f526f33fb7"
    },
    "inverse": [
      [
        1,
        4,
        "   unchanged. Only an actual successful gateway mprotect updates permissions.\n   Other mapping changes invalidate BEFORE execution, including partial errors.\n"
      ],
      [
        315,
        369,
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
