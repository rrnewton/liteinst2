"""Run the exact original test; append accounting only after unittest returns."""
import json
from pathlib import Path
import runpy
import sys

output = Path(sys.argv[1])
sys.argv = ['unittest', '-v', 'test_main_query_inventory.MainQueryInventoryTests.test_exact_sources_catalog_and_historical_denominators']
try:
    runpy.run_module('unittest', run_name='__main__')
finally:
    module = sys.modules.get('inventory_json')
    if module is not None:
        with output.open('x') as stream:
            stream.write(json.dumps(module.cache_info(), sort_keys=True)+'\n')
