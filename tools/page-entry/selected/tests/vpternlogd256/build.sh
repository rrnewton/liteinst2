#!/bin/sh
set -eu
test "$#" -eq 4
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
decoder_archive=$1
output_dir=$2
selected_dir=$(CDPATH= cd -- "$3" && pwd)
parent_dir=$(CDPATH= cd -- "$selected_dir/.." && pwd)
test -f "$decoder_archive"
test -f "$selected_dir/tests/generic/fixture.c"
mkdir -p "$output_dir"
cc_bin=${LI2_CC:-cc}
python_bin=${LI2_PYTHON:-python3}
generated_dir="$output_dir/generated"
group=$4
case "$group" in 0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32|33|34|35|36|37|38|39|40|41|42|43|44|45|46|47|48|49|50|51|52|53|54|55|56|57|58|59|60|61|62|63|64|65|66|67|68|69|70|71|72|73|74|75|76|77|78|79|80|81|82|83|84|85|86|87|88|89|90|91|92|93|94|95|96|97|98|99|100|101|102|103|104|105|106|107|108|109|110|111|112|113|114|115|116|117|118|119|120|121|122|123|124|125|126|127|128|129|130|131|132|133|134|135|136|137|138|139|140) ;; *) exit 2 ;; esac
"$python_bin" "$source_dir/generate.py" "$selected_dir/tests/vpxorq128" "$generated_dir"
"$cc_bin" -DVPX_GROUP="$group" -std=gnu11 -O2 -g -nostdlib -static -no-pie -fno-pie \
  -fno-builtin -fno-stack-protector -fno-tree-loop-distribute-patterns \
  -fno-tree-vectorize -mgeneral-regs-only -fno-asynchronous-unwind-tables \
  -ffunction-sections -fdata-sections -Wall -Wextra -Werror \
  -I"$generated_dir" -I"$selected_dir/tests/generic" -I"$selected_dir" -I"$parent_dir" \
  -Wl,-e,_start,-z,noexecstack,--gc-sections,--build-id=none \
  "$selected_dir/step_owner.c" "$selected_dir/lifecycle_loader.c" \
  "$selected_dir/tests/generic/tf_controls.c" "$source_dir/fixture.c" \
  "$source_dir/fixture.S" "$decoder_archive" -o "$output_dir/vpternlogd256-$group"
