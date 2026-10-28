/* Exact observed instruction and literal independent source seeds. */
static const unsigned char vpb_encoding[]={0x62,0xe2,0x7d,0x48,0x7a,0xc6};
struct vpb_case { const char *name; uint64_t rsi; unsigned tail; };
static const struct vpb_case vpb_cases[2][18]={
 {
  {"vpb_zmm16_rsi0000000000000000_tail6",UINT64_C(0x0000000000000000),6},
  {"vpb_zmm16_rsi0000000000000000_tail1",UINT64_C(0x0000000000000000),1},
  {"vpb_zmm16_rsi0000000000000000_tail2",UINT64_C(0x0000000000000000),2},
  {"vpb_zmm16_rsi0000000000000000_tail3",UINT64_C(0x0000000000000000),3},
  {"vpb_zmm16_rsi0000000000000000_tail4",UINT64_C(0x0000000000000000),4},
  {"vpb_zmm16_rsi0000000000000000_tail5",UINT64_C(0x0000000000000000),5},
  {"vpb_zmm16_rsi0000000000000001_tail6",UINT64_C(0x0000000000000001),6},
  {"vpb_zmm16_rsi0000000000000001_tail1",UINT64_C(0x0000000000000001),1},
  {"vpb_zmm16_rsi0000000000000001_tail2",UINT64_C(0x0000000000000001),2},
  {"vpb_zmm16_rsi0000000000000001_tail3",UINT64_C(0x0000000000000001),3},
  {"vpb_zmm16_rsi0000000000000001_tail4",UINT64_C(0x0000000000000001),4},
  {"vpb_zmm16_rsi0000000000000001_tail5",UINT64_C(0x0000000000000001),5},
  {"vpb_zmm16_rsi0000000000000080_tail6",UINT64_C(0x0000000000000080),6},
  {"vpb_zmm16_rsi0000000000000080_tail1",UINT64_C(0x0000000000000080),1},
  {"vpb_zmm16_rsi0000000000000080_tail2",UINT64_C(0x0000000000000080),2},
  {"vpb_zmm16_rsi0000000000000080_tail3",UINT64_C(0x0000000000000080),3},
  {"vpb_zmm16_rsi0000000000000080_tail4",UINT64_C(0x0000000000000080),4},
  {"vpb_zmm16_rsi0000000000000080_tail5",UINT64_C(0x0000000000000080),5},
 },
 {
  {"vpb_zmm16_rsi00000000000000ff_tail6",UINT64_C(0x00000000000000ff),6},
  {"vpb_zmm16_rsi00000000000000ff_tail1",UINT64_C(0x00000000000000ff),1},
  {"vpb_zmm16_rsi00000000000000ff_tail2",UINT64_C(0x00000000000000ff),2},
  {"vpb_zmm16_rsi00000000000000ff_tail3",UINT64_C(0x00000000000000ff),3},
  {"vpb_zmm16_rsi00000000000000ff_tail4",UINT64_C(0x00000000000000ff),4},
  {"vpb_zmm16_rsi00000000000000ff_tail5",UINT64_C(0x00000000000000ff),5},
  {"vpb_zmm16_rsi1234567800000001_tail6",UINT64_C(0x1234567800000001),6},
  {"vpb_zmm16_rsi1234567800000001_tail1",UINT64_C(0x1234567800000001),1},
  {"vpb_zmm16_rsi1234567800000001_tail2",UINT64_C(0x1234567800000001),2},
  {"vpb_zmm16_rsi1234567800000001_tail3",UINT64_C(0x1234567800000001),3},
  {"vpb_zmm16_rsi1234567800000001_tail4",UINT64_C(0x1234567800000001),4},
  {"vpb_zmm16_rsi1234567800000001_tail5",UINT64_C(0x1234567800000001),5},
  {"vpb_zmm16_rsifedcba98ffffff01_tail6",UINT64_C(0xfedcba98ffffff01),6},
  {"vpb_zmm16_rsifedcba98ffffff01_tail1",UINT64_C(0xfedcba98ffffff01),1},
  {"vpb_zmm16_rsifedcba98ffffff01_tail2",UINT64_C(0xfedcba98ffffff01),2},
  {"vpb_zmm16_rsifedcba98ffffff01_tail3",UINT64_C(0xfedcba98ffffff01),3},
  {"vpb_zmm16_rsifedcba98ffffff01_tail4",UINT64_C(0xfedcba98ffffff01),4},
  {"vpb_zmm16_rsifedcba98ffffff01_tail5",UINT64_C(0xfedcba98ffffff01),5},
 },
};
struct vpb_refusal { unsigned n; unsigned char b[7]; };
static const struct vpb_refusal vpb_refused[]={
    {6,{0x62,0xe2,0x7d,0x48,0x7a,0xc0}}, /* source_rax */
    {6,{0x62,0xe2,0x7d,0x48,0x7a,0xce}}, /* destination_zmm17 */
    {6,{0x62,0xf2,0x7d,0x48,0x7a,0xc6}}, /* destination_zmm0 */
    {6,{0x62,0xc2,0x7d,0x48,0x7a,0xc6}}, /* source_r14d */
    {6,{0x62,0xe2,0x7d,0x08,0x7a,0xc6}}, /* vl128 */
    {6,{0x62,0xe2,0x7d,0x28,0x7a,0xc6}}, /* vl256 */
    {6,{0x62,0xe2,0xfd,0x48,0x7a,0xc6}}, /* w1 */
    {6,{0x62,0xe2,0x7d,0x49,0x7a,0xc6}}, /* mask1 */
    {6,{0x62,0xe2,0x7d,0x4f,0x7a,0xc6}}, /* mask7 */
    {6,{0x62,0xe2,0x7d,0xc9,0x7a,0xc6}}, /* zero_mask1 */
    {6,{0x62,0xe2,0x7d,0xc8,0x7a,0xc6}}, /* zero_nomask */
    {6,{0x62,0xe2,0x7d,0x58,0x7a,0xc6}}, /* evex_b */
    {6,{0x62,0xe2,0x75,0x48,0x7a,0xc6}}, /* vvvv_nonreserved */
    {6,{0x62,0xe2,0x7d,0x40,0x7a,0xc6}}, /* vprime_nonreserved */
    {6,{0x62,0xe2,0x7d,0x48,0x7b,0xc6}}, /* word */
    {6,{0x62,0xe2,0x7d,0x48,0x7c,0xc6}}, /* dword */
    {6,{0x62,0xe2,0x7d,0x48,0x7a,0x06}}, /* memory_modrm */
    {7,{0xf0,0x62,0xe2,0x7d,0x48,0x7a,0xc6}}, /* prefix_f0 */
    {7,{0x66,0x62,0xe2,0x7d,0x48,0x7a,0xc6}}, /* prefix_66 */
    {7,{0xf3,0x62,0xe2,0x7d,0x48,0x7a,0xc6}}, /* prefix_f3 */
    {7,{0xf2,0x62,0xe2,0x7d,0x48,0x7a,0xc6}}, /* prefix_f2 */
    {7,{0x2e,0x62,0xe2,0x7d,0x48,0x7a,0xc6}}, /* prefix_2e */
    {7,{0x64,0x62,0xe2,0x7d,0x48,0x7a,0xc6}}, /* prefix_64 */
    {7,{0x67,0x62,0xe2,0x7d,0x48,0x7a,0xc6}}, /* prefix_67 */
    {7,{0x48,0x62,0xe2,0x7d,0x48,0x7a,0xc6}}, /* prefix_48 */
    {1,{0x62}}, /* truncated_1 */
    {2,{0x62,0xe2}}, /* truncated_2 */
    {3,{0x62,0xe2,0x7d}}, /* truncated_3 */
    {4,{0x62,0xe2,0x7d,0x48}}, /* truncated_4 */
    {5,{0x62,0xe2,0x7d,0x48,0x7a}}, /* truncated_5 */
};
