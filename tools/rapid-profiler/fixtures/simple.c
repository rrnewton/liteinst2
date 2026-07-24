typedef unsigned long long u64;

__attribute__((noinline, used)) u64 leaf_even(u64 value) {
  return value + 1;
}

__attribute__((noinline, used)) u64 leaf_odd(u64 value) {
  return value * 3 + 7;
}

__attribute__((noinline, used)) u64 branch(u64 value) {
  if ((value & 1) == 0) {
    return leaf_even(value);
  }
  return leaf_odd(value);
}

__attribute__((noinline, used)) u64 workload(u64 iterations) {
  u64 total = 0;
  for (u64 index = 0; index < iterations; ++index) {
    total += branch(index);
  }
  return total;
}
