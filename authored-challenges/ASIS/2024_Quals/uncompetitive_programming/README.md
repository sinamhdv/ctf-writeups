This challenge implements a 2D segment tree (a segment tree with a fenwick tree in every node) in C++ which represents a grid. There are 3 queries to the data structure:

- `+ r c x` will xor the value `x` with the cell `(r,c)` of the grid
- `? r1 c1 r2 c2` will show the xor of the sub-rectangle with top-left `(r1, c1)` and bottom-right `(r2, c2)`.
- `x r` will delete the leaf node of the segment tree corrsponding to row `r` (and every ancestor of that node that has no other branch except the one leading to this leaf)

There is a double-free/UAF vulnerability in the `x` query since it doesn't remove the references in the parent node to its deleted children. This can be used to overwrite a tcache fd pointer and allocate a node of the segment tree in a location that overlaps another node in a way that allows us to overwrite that node's `left` and `right` child pointers. Then we basically have arbitrary read/write. We write fake metadata for a big chunk on the heap and free it to get libc leaks from unsortedbin, and then leak the stack from libc and write a ROP payload onto the stack.

The catch is that reading and writing data from the memory is done via the xor operations to the fenwick trees in the nodes, so you'd have to reverse engineer/understand how the fenwick tree represents values in memory compared to how it calculates the query result and displays it to be able to read/write values from memory for all of these exploitation steps.

