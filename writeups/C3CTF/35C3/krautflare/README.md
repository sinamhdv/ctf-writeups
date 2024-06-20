# 35C3 CTF - Krautflare

**Summary**: Exploit a 1-day type confusion bug in Turbofan, V8's JIT compiler, to propagate incorrect type information through the sea-of-nodes graph and incorrectly eliminate a `CheckBounds` node for an array access. Then, get OOB read/write through this. Use that to get `addrof` primitive and arbitrary read/write, and eventually get RCE by writing shellcode into rwx memory mapped by a WebAssembly instance

## Vulnerability

The challenge description mentions [this](https://bugs.chromium.org/p/project-zero/issues/detail?id=1710) project zero bug report. The patches applied to v8 source code are reverting the fixing commit for that bug, and we should write a 1-day exploit for it.

The vulnerability is in `JSCallTyper` function, which determines the types for the return value of various Javascript builtin functions. Although in reality `Math.expm1(-0)` will return `-0`, in the vulnerable version of v8 `JSCallTyper` returns `Union(PlainNumber | NaN)` for the return type of this builtin function. (`PlainNumber` does not include -0). If we can use this incorrect typing to propagate incorrect type info through the sea-of-nodes graph, we can trigger an incorrect range calculation and get OOB access to an array.

There were several issues though. For example, if the compiler finds out that you are comparing the result of `Math.expm1` against -0 in `Object.is`, it will replace the `SameValue` node generated for `Object.is` by a `ObjectIsMinusZero` node, which is not useful for us (as mentioned in the bug report) (see `ReduceSameValue()` in `src/compiler/typed-optimization.cc`). So, we want it to find out that the second side of the comparison is -0 at a stage later than typed optimization. I looked at the order of the phases in the compiler pipeline and thought maybe escape analysis could be an option, since it's the phase that gets run right before simplified lowering, where we want to do the actual `CheckBounds` elimination.

In `compiler/src/escape-analysis.cc`, and the `Reduce` function which is the entrypoint function of each phase that gets called from the pipeline, I could see that `Reduce` calls `ReduceNode()`. `ReduceNode()` has a switch which does this in one of the cases:

```C++
    case IrOpcode::kLoadField: {
      Node* object = current->ValueInput(0);
      const VirtualObject* vobject = current->GetVirtualObject(object);
      Variable var;
      Node* value;
      if (vobject && !vobject->HasEscaped() &&
          vobject->FieldAt(OffsetOfFieldAccess(op)).To(&var) &&
          current->Get(var).To(&value)) {
        current->SetReplacement(value);
      } else {
        current->SetEscaped(object);
      }   
      break;
    }   
```

What I can understand roughly from this code, is that it's trying to optimize a `LoadField` opcode into a constant value, so maybe we can get it to optimiza an access to `z.a` to a constant minus zero if `z` is `{a: -0}`. This worked and this issue was solved.

Another issue is that the call to `Math.expm1` gets replaced with a `Float64Expm1` node, and the typer will correctly mark the return value of a `Float64Expm1` as `Number`. This is because the bug is only in `typer.cc` and in `JSCallTyper`, not `operation-typer.cc`, so it will only affect `JSCall`s to the `Math.expm1` builtin function.

To solve this, we have to somehow make the compiler think that the argument to `Math.expm1` can be something other that a float64 too, so it doesn't optimize it to a `Float64Expm1` and leaves it as a `Call` node. To do this, we optimize our function once while we've called it only with number arguments. Then, we call it with another type of operand (For example, `f("0")`) to force a deoptimization and record the feedback data that the input variable is not necessarily a number.
Then, we optimize the function again. This time, `Math.expm1` will stay a `Call` node to the builtin function, and the typer determines its return type as `PlainNumber | NaN` as we expect.

Now the result of the `Object.is` call is a boolean that gets determined to be a false constant in the third typer run in simplified lowering phase. I don't exactly know why this type determined in that phase doesn't get displayed in the sea-of-nodes graph in Turbolizer, but still using `--trace-representation` will log it and show it.

If we multiply the result of `Object.is` into an integer, the resulting number will be assumed to be always zero by the typer, but it can actually be equal to the integer we multiplied it in if the input was `-0` and `Object.is` returned true.

We use this for OOB access into an array. The third issue that I faced was that if I tried to use the OOB primitive to write the length field of an array and return the same array to be used as an OOB primitive for the rest of the exploit, the checkbounds node did not get eliminated. I don't exactly know the reason for this (I tried to single-step through the `VisitCheckBounds` function in `simplified-lowering.cc` in gdb for both versions of the code to compare them, and apparently for the non-working version, it doesn't detect the length of the array we defined locally to be a constant value, and it incorrectly assumes that the range of its length is from 0 to the max smi value possible). Also, it turns out that if you don't return the array from the function and try to do the rest of the exploit inside the function, the array that gets created locally does not get allocated as a full normal object. It only allocates a `FixedDoubleArray` for its `elements` field and doesn't allocate the `JSArray` object itself for optimization. So, the thing I ended up doing was to define a second array inside the function that I will return, and use the checkbounds slimination on the first array to write a huge value into the length field of the second array and then return the second array to be used as an arbitrary OOB read/write primitive for the rest of the exploit.

The rest is the same as other typical v8 challenges without the sandbox. I used an array of objects in front of the oob array to get `addrof` primitive, and then overwrote the data ptr of a typed array to get arbitrary read/write. I also loaded a wasm instance to map an rwx page and used the arbitrary read/write primitive to write shellcode into the rwx memory.
