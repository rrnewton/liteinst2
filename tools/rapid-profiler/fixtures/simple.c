typedef unsigned long long u64;

#define PROFILED __attribute__((noinline, used, optnone))

PROFILED u64 leaf_even(u64 value) {
  return value + 1;
}

PROFILED u64 leaf_odd(u64 value) {
  return value * 3 + 7;
}

PROFILED u64 branch(u64 value) {
  return leaf_even(value) + leaf_even(value + 1) + leaf_odd(value) +
         leaf_odd(value + 1);
}

PROFILED u64 workload(u64 iterations) {
  u64 total = 0;
  for (u64 index = 0; index < iterations; ++index) {
    total += branch(index);
  }
  return total;
}
