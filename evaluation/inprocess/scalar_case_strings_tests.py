"""Typed round trips and malformed references for the compact numerical receipt."""
import copy,json,unittest
import scalar_case_strings as codec


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)


def fixture():
    repeated='0123456789abcdef'*4
    captures={'stdout':{'bytes':0,'sha256':repeated},'stderr':{'bytes':0,'sha256':repeated}}
    return dict(case_encoding='shared-numerical-columns-v1',case_columns=['captures','sample','value'],
        case_subcolumns={'sample':['a','b']},cases=[
            [1,7,captures,[3,0,False],[None,False,0,True,1,1.0,{'$s':0},{'$d':[]},{'$o':[0]},repeated]],
            [0,5,{},None,{'$s':{'$s':True}}],
            [0,0,None,None,None]],
        mapping_controls=dict(planned=2,status='failed',cases=[{'a':None,'b':False},{'a':0}]))


class CompactPublicTests(unittest.TestCase):
    def test_exact_json_types_missing_null_and_reserved_markers(self):
        source=fixture();before=canonical(source)
        encoded=json.loads(canonical(codec.project(source)))
        self.assertEqual(canonical(codec.restore(encoded)),before)
        self.assertEqual(canonical(source),before)

    def test_empty_population(self):
        source=dict(case_encoding='shared-numerical-columns-v1',case_columns=[],case_subcolumns={},cases=[])
        self.assertEqual(canonical(codec.restore(codec.project(source))),canonical(source))

    def test_original_missing_padding_cannot_hide_values(self):
        source=fixture();source['cases'][2][2]='hidden'
        with self.assertRaisesRegex(ValueError,'canonical null padding'):codec.project(source)

    def test_sparse_population_must_be_complete(self):
        encoded=codec.project(fixture());encoded['cases'][0].append(1)
        with self.assertRaisesRegex(ValueError,'complete sparse'):codec.restore(encoded)

    def test_boolean_string_index_is_not_integer(self):
        encoded=codec.project(fixture())
        def replace(value):
            if type(value)is dict:
                if set(value)=={'$s'}:value['$s']=True;return True
                return any(replace(item)for item in value.values())
            if type(value)is list:return any(replace(item)for item in value)
            return False
        self.assertTrue(replace(encoded['cases']))
        with self.assertRaisesRegex(ValueError,'exact string reference'):codec.restore(encoded)

    def test_capture_mask_cannot_create_missing_field(self):
        encoded=codec.project(fixture());encoded['case_capture_rows']|=4
        with self.assertRaisesRegex(ValueError,'actually present'):codec.restore(encoded)

    def test_string_table_must_be_unique(self):
        encoded=codec.project(fixture());encoded['case_strings']*=2
        with self.assertRaisesRegex(ValueError,'unique string table'):codec.restore(encoded)

    def test_mapping_rows_keep_presence_and_values(self):
        encoded=codec.project(fixture());encoded['mapping_controls']['cases'][0].append(None)
        with self.assertRaisesRegex(ValueError,'complete sparse'):codec.restore(encoded)


if __name__=='__main__':unittest.main()
