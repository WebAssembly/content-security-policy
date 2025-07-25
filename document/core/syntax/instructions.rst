.. index:: ! instruction, code, stack machine, operand, operand stack
   pair: abstract syntax; instruction
.. _syntax-instr:

Instructions
------------

WebAssembly code consists of sequences of *instructions*.
Its computational model is based on a *stack machine* in that instructions manipulate values on an implicit *operand stack*,
consuming (popping) argument values and producing or returning (pushing) result values.

In addition to dynamic operands from the stack, some instructions also have static *immediate* arguments,
typically :ref:`indices <syntax-index>` or type annotations,
which are part of the instruction itself.

Some instructions are :ref:`structured <syntax-instr-control>` in that they bracket nested sequences of instructions.

The following sections group instructions into a number of different categories.


.. index:: ! numeric instruction, value, value type, integer, floating-point, two's complement
   pair: abstract syntax; instruction
.. _syntax-sx:
.. _syntax-const:
.. _syntax-iunop:
.. _syntax-ibinop:
.. _syntax-itestop:
.. _syntax-irelop:
.. _syntax-funop:
.. _syntax-fbinop:
.. _syntax-ftestop:
.. _syntax-frelop:
.. _syntax-instr-numeric:

Numeric Instructions
~~~~~~~~~~~~~~~~~~~~

Numeric instructions provide basic operations over numeric :ref:`values <syntax-value>` of specific :ref:`type <syntax-numtype>`.
These operations closely match respective operations available in hardware.

.. math::
   \begin{array}{llrl}
   \production{width} & \X{nn}, \X{mm} &::=&
     \K{32} ~|~ \K{64} \\
   \production{signedness} & \sx &::=&
     \K{u} ~|~ \K{s} \\
   \production{instruction} & \instr &::=&
     \K{i}\X{nn}\K{.}\CONST~\xref{syntax/values}{syntax-int}{\uX{\X{nn}}} ~|~
     \K{f}\X{nn}\K{.}\CONST~\xref{syntax/values}{syntax-float}{\fX{\X{nn}}} \\&&|&
     \K{i}\X{nn}\K{.}\iunop ~|~
     \K{f}\X{nn}\K{.}\funop \\&&|&
     \K{i}\X{nn}\K{.}\ibinop ~|~
     \K{f}\X{nn}\K{.}\fbinop \\&&|&
     \K{i}\X{nn}\K{.}\itestop \\&&|&
     \K{i}\X{nn}\K{.}\irelop ~|~
     \K{f}\X{nn}\K{.}\frelop \\&&|&
     \K{i}\X{nn}\K{.}\EXTEND\K{8\_s} ~|~
     \K{i}\X{nn}\K{.}\EXTEND\K{16\_s} ~|~
     \K{i64.}\EXTEND\K{32\_s} \\&&|&
     \K{i32.}\WRAP\K{\_i64} ~|~
     \K{i64.}\EXTEND\K{\_i32}\K{\_}\sx ~|~
     \K{i}\X{nn}\K{.}\TRUNC\K{\_f}\X{mm}\K{\_}\sx \\&&|&
     \K{i}\X{nn}\K{.}\TRUNC\K{\_sat\_f}\X{mm}\K{\_}\sx \\&&|&
     \K{f32.}\DEMOTE\K{\_f64} ~|~
     \K{f64.}\PROMOTE\K{\_f32} ~|~
     \K{f}\X{nn}\K{.}\CONVERT\K{\_i}\X{mm}\K{\_}\sx \\&&|&
     \K{i}\X{nn}\K{.}\REINTERPRET\K{\_f}\X{nn} ~|~
     \K{f}\X{nn}\K{.}\REINTERPRET\K{\_i}\X{nn} \\&&|&
     \dots \\
   \production{integer unary operator} & \iunop &::=&
     \K{clz} ~|~
     \K{ctz} ~|~
     \K{popcnt} \\
   \production{integer binary operator} & \ibinop &::=&
     \K{add} ~|~
     \K{sub} ~|~
     \K{mul} ~|~
     \K{div\_}\sx ~|~
     \K{rem\_}\sx \\&&|&
     \K{and} ~|~
     \K{or} ~|~
     \K{xor} ~|~
     \K{shl} ~|~
     \K{shr\_}\sx ~|~
     \K{rotl} ~|~
     \K{rotr} \\
   \production{floating-point unary operator} & \funop &::=&
     \K{abs} ~|~
     \K{neg} ~|~
     \K{sqrt} ~|~
     \K{ceil} ~|~ 
     \K{floor} ~|~ 
     \K{trunc} ~|~ 
     \K{nearest} \\
   \production{floating-point binary operator} & \fbinop &::=&
     \K{add} ~|~
     \K{sub} ~|~
     \K{mul} ~|~
     \K{div} ~|~
     \K{min} ~|~
     \K{max} ~|~
     \K{copysign} \\
   \production{integer test operator} & \itestop &::=&
     \K{eqz} \\
   \production{integer relational operator} & \irelop &::=&
     \K{eq} ~|~
     \K{ne} ~|~
     \K{lt\_}\sx ~|~
     \K{gt\_}\sx ~|~
     \K{le\_}\sx ~|~
     \K{ge\_}\sx \\
   \production{floating-point relational operator} & \frelop &::=&
     \K{eq} ~|~
     \K{ne} ~|~
     \K{lt} ~|~
     \K{gt} ~|~
     \K{le} ~|~
     \K{ge} \\
   \end{array}

Numeric instructions are divided by :ref:`number type <syntax-numtype>`.
For each type, several subcategories can be distinguished:

* *Constants*: return a static constant.

* *Unary Operations*: consume one operand and produce one result of the respective type.

* *Binary Operations*: consume two operands and produce one result of the respective type.

* *Tests*: consume one operand of the respective type and produce a Boolean integer result.

* *Comparisons*: consume two operands of the respective type and produce a Boolean integer result.

* *Conversions*: consume a value of one type and produce a result of another
  (the source type of the conversion is the one after the ":math:`\K{\_}`").

Some integer instructions come in two flavors,
where a signedness annotation |sx| distinguishes whether the operands are to be :ref:`interpreted <aux-signed>` as :ref:`unsigned <syntax-uint>` or :ref:`signed <syntax-sint>` integers.
For the other integer instructions, the use of two's complement for the signed interpretation means that they behave the same regardless of signedness.


.. _syntax-unop:
.. _syntax-binop:
.. _syntax-testop:
.. _syntax-relop:
.. _syntax-cvtop:

Conventions
...........

Occasionally, it is convenient to group operators together according to the following grammar shorthands:

.. math::
   \begin{array}{llrl}
   \production{unary operator} & \unop &::=&
     \iunop ~|~
     \funop ~|~
     \EXTEND{N}\K{\_s} \\
   \production{binary operator} & \binop &::=& \ibinop ~|~ \fbinop \\
   \production{test operator} & \testop &::=& \itestop \\
   \production{relational operator} & \relop &::=& \irelop ~|~ \frelop \\
   \production{conversion operator} & \cvtop &::=&
     \WRAP ~|~
     \EXTEND ~|~
     \TRUNC ~|~
     \TRUNC\K{\_sat} ~|~
     \CONVERT ~|~
     \DEMOTE ~|~
     \PROMOTE ~|~
     \REINTERPRET \\
   \end{array}


.. index:: ! vector instruction, numeric vector, number, value, value type, SIMD
   pair: abstract syntax; instruction
.. _syntax-laneidx:
.. _syntax-shape:
.. _syntax-half:
.. _syntax-vvunop:
.. _syntax-vvbinop:
.. _syntax-vvternop:
.. _syntax-vvtestop:
.. _syntax-vitestop:
.. _syntax-virelop:
.. _syntax-vfrelop:
.. _syntax-vishiftop:
.. _syntax-viunop:
.. _syntax-vibinop:
.. _syntax-viminmaxop:
.. _syntax-visatbinop:
.. _syntax-vfunop:
.. _syntax-vfbinop:
.. _syntax-rvfbinop:
.. _syntax-rvfternop:
.. _syntax-instr-vec:
.. _syntax-instr-relaxed:

Vector Instructions
~~~~~~~~~~~~~~~~~~~

Vector instructions (also known as *SIMD* instructions, *single instruction multiple data*) provide basic operations over :ref:`values <syntax-value>` of :ref:`vector type <syntax-vectype>`.

.. math::
   \begin{array}{llrl}
   \production{ishape} & \ishape &::=&
     \K{i8x16} ~|~ \K{i16x8} ~|~ \K{i32x4} ~|~ \K{i64x2} \\
   \production{fshape} & \fshape &::=&
     \K{f32x4} ~|~ \K{f64x2} \\
   \production{shape} & \shape &::=&
     \ishape ~|~ \fshape \\
   \production{half} & \half &::=&
     \K{low} ~|~ \K{high} \\
   \production{lane index} & \laneidx &::=& \u8 \\
   \end{array}

.. math::
   \begin{array}{llrl}
   \production{instruction} & \instr &::=&
     \dots \\&&|&
     \K{v128.}\VCONST~\i128 \\&&|&
     \K{v128.}\vvunop \\&&|&
     \K{v128.}\vvbinop \\&&|&
     \K{v128.}\vvternop \\&&|&
     \K{v128.}\vvtestop \\&&|&
     \K{i8x16.}\SHUFFLE~\laneidx^{16} \\&&|&
     \K{i8x16.}\SWIZZLE \\&&|&
     \shape\K{.}\SPLAT \\&&|&
     \K{i8x16.}\EXTRACTLANE\K{\_}\sx~\laneidx ~|~
     \K{i16x8.}\EXTRACTLANE\K{\_}\sx~\laneidx \\&&|&
     \K{i32x4.}\EXTRACTLANE~\laneidx ~|~
     \K{i64x2.}\EXTRACTLANE~\laneidx \\&&|&
     \fshape\K{.}\EXTRACTLANE~\laneidx \\&&|&
     \shape\K{.}\REPLACELANE~\laneidx \\&&|&
     \K{i8x16}\K{.}\virelop ~|~
     \K{i16x8}\K{.}\virelop ~|~
     \K{i32x4}\K{.}\virelop \\&&|&
     \K{i64x2.}\K{eq} ~|~
     \K{i64x2.}\K{ne} ~|~
     \K{i64x2.}\K{lt\_s} ~|~
     \K{i64x2.}\K{gt\_s} ~|~
     \K{i64x2.}\K{le\_s} ~|~
     \K{i64x2.}\K{ge\_s} \\&&|&
     \fshape\K{.}\vfrelop \\&&|&
     \ishape\K{.}\viunop ~|~
     \K{i8x16.}\VPOPCNT \\&&|&
     \K{i16x8.}\Q15MULRSAT\K{\_s} \\ &&|&
     \K{i32x4.}\DOT\K{\_i16x8\_s} \\ &&|&
     \fshape\K{.}\vfunop \\&&|&
     \ishape\K{.}\vitestop \\ &&|&
     \ishape\K{.}\BITMASK \\ &&|&
     \K{i8x16.}\NARROW\K{\_i16x8\_}\sx ~|~
     \K{i16x8.}\NARROW\K{\_i32x4\_}\sx \\&&|&
     \K{i16x8.}\VEXTEND\K{\_}\half\K{\_i8x16\_}\sx ~|~
     \K{i32x4.}\VEXTEND\K{\_}\half\K{\_i16x8\_}\sx \\&&|&
     \K{i64x2.}\VEXTEND\K{\_}\half\K{\_i32x4\_}\sx \\&&|&
     \ishape\K{.}\vishiftop \\&&|&
     \ishape\K{.}\vibinop \\&&|&
     \K{i8x16.}\viminmaxop ~|~
     \K{i16x8.}\viminmaxop ~|~
     \K{i32x4.}\viminmaxop \\&&|&
     \K{i8x16.}\visatbinop ~|~
     \K{i16x8.}\visatbinop \\&&|&
     \K{i16x8.}\K{mul} ~|~
     \K{i32x4.}\K{mul} ~|~
     \K{i64x2.}\K{mul} \\&&|&
     \K{i8x16.}\AVGR\K{\_u} ~|~
     \K{i16x8.}\AVGR\K{\_u} \\&&|&
     \K{i16x8.}\EXTMUL\K{\_}\half\K{\_i8x16\_}\sx ~|~
     \K{i32x4.}\EXTMUL\K{\_}\half\K{\_i16x8\_}\sx ~|~
     \K{i64x2.}\EXTMUL\K{\_}\half\K{\_i32x4\_}\sx \\ &&|&
     \K{i16x8.}\EXTADDPAIRWISE\K{\_i8x16\_}\sx ~|~
     \K{i32x4.}\EXTADDPAIRWISE\K{\_i16x8\_}\sx \\ &&|&
     \fshape\K{.}\vfbinop \\&&|&
     \K{i32x4.}\VTRUNC\K{\_sat\_f32x4\_}\sx ~|~
     \K{i32x4.}\VTRUNC\K{\_sat\_f64x2\_}\sx\K{\_zero} \\&&|&
     \K{f32x4.}\VCONVERT\K{\_i32x4\_}\sx ~|~
     \K{f32x4.}\VDEMOTE\K{\_f64x2\_zero} \\&&|&
     \K{f64x2.}\VCONVERT\K{\_low\_i32x4\_}\sx ~|~
     \K{f64x2.}\VPROMOTE\K{\_low\_f32x4} \\
     & &|& \K{i8x16.}\RELAXEDSWIZZLE \\
     & &|& \K{i16x8.}\RELAXEDQ15MULRS \\
     & &|& \K{i32x4.}\RELAXEDTRUNC\K{\_f32x4\_}\sx \\
     & &|& \K{i16x8.}\RELAXEDDOT\K{\_i8x16\_i7x16\_s} \\
     & &|& \K{i32x4.}\RELAXEDDOT\K{\_i8x16\_i7x16\_add\_s} \\
     & &|& \ishape\K{.}\RELAXEDLANESELECT \\
     & &|& \fshape\K{.}\rvfternop \\
     & &|& \fshape\K{.}\rvfbinop \\
     & &|& \dots \\
   \end{array}

.. math::
   \begin{array}{llrl}
   \production{vector bitwise unary operator} & \vvunop &::=&
     \K{not} \\
   \production{vector bitwise binary operator} & \vvbinop &::=&
     \K{and} ~|~
     \K{andnot} ~|~
     \K{or} ~|~
     \K{xor} \\
   \production{vector bitwise ternary operator} & \vvternop &::=&
     \K{bitselect} \\
   \production{vector bitwise test operator} & \vvtestop &::=&
     \K{any\_true} \\
   \production{vector integer test operator} & \vitestop &::=&
     \K{all\_true} \\
   \production{vector integer relational operator} & \virelop &::=&
     \K{eq} ~|~
     \K{ne} ~|~
     \K{lt\_}\sx ~|~
     \K{gt\_}\sx ~|~
     \K{le\_}\sx ~|~
     \K{ge\_}\sx \\
   \production{vector floating-point relational operator} & \vfrelop &::=&
     \K{eq} ~|~
     \K{ne} ~|~
     \K{lt} ~|~
     \K{gt} ~|~
     \K{le} ~|~
     \K{ge} \\
   \production{vector integer unary operator} & \viunop &::=&
     \K{abs} ~|~
     \K{neg} \\
   \production{vector integer binary operator} & \vibinop &::=&
     \K{add} ~|~
     \K{sub} \\
   \production{vector integer binary min/max operator} & \viminmaxop &::=&
     \K{min\_}\sx ~|~
     \K{max\_}\sx \\
   \production{vector integer saturating binary operator} & \visatbinop &::=&
     \K{add\_sat\_}\sx ~|~
     \K{sub\_sat\_}\sx \\
   \production{vector integer shift operator} & \vishiftop &::=&
     \K{shl} ~|~
     \K{shr\_}\sx \\
   \production{vector floating-point unary operator} & \vfunop &::=&
     \K{abs} ~|~
     \K{neg} ~|~
     \K{sqrt} ~|~
     \K{ceil} ~|~
     \K{floor} ~|~
     \K{trunc} ~|~
     \K{nearest} \\
   \production{vector floating-point binary operator} & \vfbinop &::=&
     \K{add} ~|~
     \K{sub} ~|~
     \K{mul} ~|~
     \K{div} ~|~
     \K{min} ~|~
     \K{max} ~|~
     \K{pmin} ~|~
     \K{pmax} \\
   \production{relaxed vector floating-point binary operator} & \rvfbinop &::=&
     \K{relaxed\_min} ~|~
     \K{relaxed\_max} \\
   \production{relaxed vector floating-point ternary operator} & \rvfternop &::=&
     \K{relaxed\_madd} ~|~
     \K{relaxed\_nmadd} \\
   \end{array}

.. _syntax-vec-shape:

Vector instructions have a naming convention involving a prefix that
determines how their operands will be interpreted.
This prefix describes the *shape* of the operand,
written :math:`t\K{x}N`, and consisting of a packed :ref:`numeric type <syntax-numtype>` :math:`t` and the number of *lanes* :math:`N` of that type.
Operations are performed point-wise on the values of each lane.

.. note::
   For example, the shape :math:`\K{i32x4}` interprets the operand
   as four |i32| values, packed into an |i128|.
   The bit width of the numeric type :math:`t` times :math:`N` always is 128.

Instructions prefixed with :math:`\K{v128}` do not involve a specific interpretation, and treat the |V128| as an |i128| value or a vector of 128 individual bits.

Vector instructions can be grouped into several subcategories:

* *Constants*: return a static constant.

* *Unary Operations*: consume one |V128| operand and produce one |V128| result.

* *Binary Operations*: consume two |V128| operands and produce one |V128| result.

* *Ternary Operations*: consume three |V128| operands and produce one |V128| result.

* *Tests*: consume one |V128| operand and produce a Boolean integer result.

* *Shifts*: consume a |v128| operand and a |i32| operand, producing one |V128| result.

* *Splats*: consume a value of numeric type and produce a |V128| result of a specified shape.

* *Extract lanes*: consume a |V128| operand and return the numeric value in a given lane.

* *Replace lanes*: consume a |V128| operand and a numeric value for a given lane, and produce a |V128| result.

Some vector instructions have a signedness annotation |sx| which distinguishes whether the elements in the operands are to be :ref:`interpreted <aux-signed>` as :ref:`unsigned <syntax-uint>` or :ref:`signed <syntax-sint>` integers.
For the other vector instructions, the use of two's complement for the signed interpretation means that they behave the same regardless of signedness.


.. _syntax-vunop:
.. _syntax-vbinop:
.. _syntax-vrelop:
.. _syntax-vternop:
.. _syntax-vtestop:
.. _syntax-vcvtop:

Conventions
...........

Occasionally, it is convenient to group operators together according to the following grammar shorthands:

.. math::
   \begin{array}{llrl}
   \production{unary operator} & \vunop &::=&
     \viunop ~|~
     \vfunop ~|~
     \VPOPCNT \\
   \production{binary operator} & \vbinop &::=&
     \vibinop ~|~ \vfbinop \\&&|&
     \viminmaxop ~|~ \visatbinop \\&&|&
     \rvfbinop \\&&|&
     \VMUL ~|~
     \AVGR\K{\_u} ~|~
     \Q15MULRSAT\K{\_s} \\&&|&
     \RELAXEDQ15MULRS\K{\_s} \\
   \production{ternary operator} & \vternop &::=&
     \vvternop ~|~
     \rvfternop \\
   \production{test operator} & \vtestop &::=&
     \vitestop \\
   \production{relational operator} & \vrelop &::=&
     \virelop ~|~ \vfrelop \\
   \production{conversion operator} & \vcvtop &::=&
     \VEXTEND ~|~
     \VTRUNC\K{\_sat} ~|~
     \VCONVERT ~|~
     \VDEMOTE ~|~
     \VPROMOTE ~|~
     \RELAXEDTRUNC \\
   \end{array}


.. index:: ! reference instruction, reference, null, cast, heap type, reference type
   pair: abstract syntax; instruction
.. _syntax-ref.null:
.. _syntax-ref.func:
.. _syntax-ref.is_null:
.. _syntax-ref.as_non_null:
.. _syntax-ref.eq:
.. _syntax-ref.test:
.. _syntax-ref.cast:
.. _syntax-instr-ref:

Reference Instructions
~~~~~~~~~~~~~~~~~~~~~~

Instructions in this group are concerned with accessing :ref:`references <syntax-reftype>`.

.. math::
   \begin{array}{llrl}
   \production{instruction} & \instr &::=&
     \dots \\&&|&
     \REFNULL~\heaptype \\&&|&
     \REFFUNC~\funcidx \\&&|&
     \REFISNULL \\&&|&
     \REFASNONNULL \\&&|&
     \REFEQ \\&&|&
     \REFTEST~\reftype \\&&|&
     \REFCAST~\reftype \\
   \end{array}

The |REFNULL| and |REFFUNC| instructions produce a :ref:`null <syntax-null>` value or a reference to a given function, respectively.

The instruction |REFISNULL| checks for null,
while |REFASNONNULL| converts a :ref:`nullable <syntax-reftype>` to a non-null one, and :ref:`traps <trap>` if it encounters null.

The |REFEQ| compares two references.

The instructions |REFTEST| and |REFCAST| test the :ref:`dynamic type <type-inst>` of a reference operand.
The former merely returns the result of the test,
while the latter performs a downcast and :ref:`traps <trap>` if the operand's type does not match.

.. note::
   The |BRONCAST| and |BRONCASTFAIL| instructions provides versions of the latter that branch depending on the success of the downcast instead of trapping.


.. index:: reference instruction, reference, null, heap type, reference type
   pair: abstract syntax; instruction

.. _syntax-struct.new:
.. _syntax-struct.new_default:
.. _syntax-struct.get:
.. _syntax-struct.get_s:
.. _syntax-struct.get_u:
.. _syntax-struct.set:
.. _syntax-array.new:
.. _syntax-array.new_default:
.. _syntax-array.new_fixed:
.. _syntax-array.new_data:
.. _syntax-array.new_elem:
.. _syntax-array.get:
.. _syntax-array.get_s:
.. _syntax-array.get_u:
.. _syntax-array.set:
.. _syntax-array.len:
.. _syntax-array.fill:
.. _syntax-array.copy:
.. _syntax-array.init_data:
.. _syntax-array.init_elem:
.. _syntax-ref.i31:
.. _syntax-i31.get_s:
.. _syntax-i31.get_u:
.. _syntax-any.convert_extern:
.. _syntax-extern.convert_any:
.. _syntax-instr-struct:
.. _syntax-instr-array:
.. _syntax-instr-i31:
.. _syntax-instr-extern:

Aggregate Instructions
~~~~~~~~~~~~~~~~~~~~~~

Instructions in this group are concerned with creating and accessing :ref:`references <syntax-reftype>` to :ref:`aggregate <syntax-aggrtype>` types.

.. math::
   \begin{array}{llrl}
   \production{instruction} & \instr &::=&
     \dots \\&&|&
     \STRUCTNEW~\typeidx \\&&|&
     \STRUCTNEWDEFAULT~\typeidx \\&&|&
     \STRUCTGET~\typeidx~\fieldidx \\&&|&
     \STRUCTGET\K{\_}\sx~\typeidx~\fieldidx \\&&|&
     \STRUCTSET~\typeidx~\fieldidx \\&&|&
     \ARRAYNEW~\typeidx \\&&|&
     \ARRAYNEWFIXED~\typeidx~\u32 \\&&|&
     \ARRAYNEWDEFAULT~\typeidx \\&&|&
     \ARRAYNEWDATA~\typeidx~\dataidx \\&&|&
     \ARRAYNEWELEM~\typeidx~\elemidx \\&&|&
     \ARRAYGET~\typeidx \\&&|&
     \ARRAYGET\K{\_}\sx~\typeidx \\&&|&
     \ARRAYSET~\typeidx \\&&|&
     \ARRAYLEN \\&&|&
     \ARRAYFILL~\typeidx \\&&|&
     \ARRAYCOPY~\typeidx~\typeidx \\&&|&
     \ARRAYINITDATA~\typeidx~\dataidx \\&&|&
     \ARRAYINITELEM~\typeidx~\elemidx \\&&|&
     \REFI31 \\&&|&
     \I31GET\K{\_}\sx \\&&|&
     \ANYCONVERTEXTERN \\&&|&
     \EXTERNCONVERTANY \\
   \end{array}

The instructions |STRUCTNEW| and |STRUCTNEWDEFAULT| allocate a new :ref:`structure <syntax-structtype>`, initializing them either with operands or with default values.
The remaining instructions on structs access individual fields,
allowing for different sign extension modes in the case of :ref:`packed <syntax-packedtype>` storage types.

Similarly, :ref:`arrays <syntax-arraytype>` can be allocated either with an explicit initialization operand or a default value.
Furthermore, |ARRAYNEWFIXED| allocates an array with statically fixed size,
and |ARRAYNEWDATA| and |ARRAYNEWELEM| allocate an array and initialize it from a :ref:`data <syntax-data>` or :ref:`element <syntax-elem>` segment, respectively.
|ARRAYGET|, |ARRAYGETS|, |ARRAYGETU|, and |ARRAYSET| access individual slots,
again allowing for different sign extension modes in the case of a :ref:`packed <syntax-packedtype>` storage type.
|ARRAYLEN| produces the length of an array.
|ARRAYFILL| fills a specified slice of an array with a given value and |ARRAYCOPY|, |ARRAYINITDATA|, and |ARRAYINITELEM| copy elements to a specified slice of an array from a given array, data segment, or element segment, respectively.

The instructions |REFI31| and :math:`\I31GET\K{\_}\sx` convert between type |I31| and an unboxed :ref:`scalar <syntax-i31>`.

The instructions |ANYCONVERTEXTERN| and |EXTERNCONVERTANY| allow lossless conversion between references represented as type :math:`(\REF~\NULL~\EXTERN)`| and as :math:`(\REF~\NULL~\ANY)`.

.. index:: ! parametric instruction, value type
   pair: abstract syntax; instruction
.. _syntax-instr-parametric:

Parametric Instructions
~~~~~~~~~~~~~~~~~~~~~~~

Instructions in this group can operate on operands of any :ref:`value type <syntax-valtype>`.

.. math::
   \begin{array}{llrl}
   \production{instruction} & \instr &::=&
     \dots \\&&|&
     \DROP \\&&|&
     \SELECT~(\valtype^\ast)^? \\
   \end{array}

The |DROP| instruction simply throws away a single operand.

The |SELECT| instruction selects one of its first two operands based on whether its third operand is zero or not.
It may include a :ref:`value type <syntax-valtype>` determining the type of these operands.
If missing, the operands must be of :ref:`numeric <syntax-numtype>` or :ref:`vector <syntax-vectype>` type.

.. note::
   In future versions of WebAssembly, the type annotation on |SELECT| may allow for more than a single value being selected at the same time.


.. index:: ! variable instruction, local, global, local index, global index
   pair: abstract syntax; instruction
.. _syntax-instr-variable:

Variable Instructions
~~~~~~~~~~~~~~~~~~~~~

Variable instructions are concerned with access to :ref:`local <syntax-local>` or :ref:`global <syntax-global>` variables.

.. math::
   \begin{array}{llrl}
   \production{instruction} & \instr &::=&
     \dots \\&&|&
     \LOCALGET~\localidx \\&&|&
     \LOCALSET~\localidx \\&&|&
     \LOCALTEE~\localidx \\&&|&
     \GLOBALGET~\globalidx \\&&|&
     \GLOBALSET~\globalidx \\
   \end{array}

These instructions get or set the values of variables, respectively.
The |LOCALTEE| instruction is like |LOCALSET| but also returns its argument.


.. index:: ! table instruction, table, table index, trap
   pair: abstract syntax; instruction
.. _syntax-instr-table:
.. _syntax-table.get:
.. _syntax-table.set:
.. _syntax-table.size:
.. _syntax-table.grow:
.. _syntax-table.fill:

Table Instructions
~~~~~~~~~~~~~~~~~~

Instructions in this group are concerned with tables :ref:`table <syntax-table>`.

.. math::
   \begin{array}{llrl}
   \production{instruction} & \instr &::=&
     \dots \\&&|&
     \TABLEGET~\tableidx \\&&|&
     \TABLESET~\tableidx \\&&|&
     \TABLESIZE~\tableidx \\&&|&
     \TABLEGROW~\tableidx \\&&|&
     \TABLEFILL~\tableidx \\&&|&
     \TABLECOPY~\tableidx~\tableidx \\&&|&
     \TABLEINIT~\tableidx~\elemidx \\&&|&
     \ELEMDROP~\elemidx \\
   \end{array}

The |TABLEGET| and |TABLESET| instructions load or store an element in a table, respectively.

The |TABLESIZE| instruction returns the current size of a table.
The |TABLEGROW| instruction grows table by a given delta and returns the previous size, or :math:`-1` if enough space cannot be allocated.
It also takes an initialization value for the newly allocated entries.

The |TABLEFILL| instruction sets all entries in a range to a given value.

The |TABLECOPY| instruction copies elements from a source table region to a possibly overlapping destination region; the first index denotes the destination.
The |TABLEINIT| instruction copies elements from a :ref:`passive element segment <syntax-elem>` into a table.
The |ELEMDROP| instruction prevents further use of a passive element segment. This instruction is intended to be used as an optimization hint. After an element segment is dropped its elements can no longer be retrieved, so the memory used by this segment may be freed.

An additional instruction that accesses a table is the :ref:`control instruction <syntax-instr-control>` |CALLINDIRECT|.


.. index:: ! memory instruction, memory, memory index, page size, little endian, trap
   pair: abstract syntax; instruction
.. _syntax-loadn:
.. _syntax-storen:
.. _syntax-memarg:
.. _syntax-lanewidth:
.. _syntax-instr-memory:

Memory Instructions
~~~~~~~~~~~~~~~~~~~

Instructions in this group are concerned with linear :ref:`memory <syntax-mem>`.

.. math::
   \begin{array}{llrl}
   \production{memory immediate} & \memarg &::=&
     \{ \OFFSET~\u64, \ALIGN~\u32 \} \\
   \production{type width} & \X{nn} &::=&
     \K{32} ~|~ \K{64} \\
   \production{lane width} & \X{ww} &::=&
     \K{8} ~|~ \K{16} ~|~ \K{32} ~|~ \K{64} \\
   \production{instruction} & \instr &::=&
     \dots \\&&|&
     \K{i}\X{nn}\K{.}\LOAD~\memidx~\memarg ~|~
     \K{f}\X{nn}\K{.}\LOAD~\memidx~\memarg \\&&|&
     \K{v128.}\LOAD~\memidx~\memarg \\&&|&
     \K{i}\X{nn}\K{.}\STORE~\memidx~\memarg ~|~
     \K{f}\X{nn}\K{.}\STORE~\memidx~\memarg \\&&|&
     \K{v128.}\STORE~\memidx~\memarg \\&&|&
     \K{i}\X{nn}\K{.}\LOAD\K{8\_}\sx~\memidx~\memarg ~|~
     \K{i}\X{nn}\K{.}\LOAD\K{16\_}\sx~\memidx~\memarg ~|~
     \K{i64.}\LOAD\K{32\_}\sx~\memidx~\memarg \\&&|&
     \K{v128.}\LOAD\K{8x8\_}\sx~\memidx~\memarg ~|~
     \K{v128.}\LOAD\K{16x4\_}\sx~\memidx~\memarg ~|~
     \K{v128.}\LOAD\K{32x2\_}\sx~\memidx~\memarg \\&&|&
     \K{v128.}\LOAD\K{32\_zero}~\memidx~\memarg ~|~
     \K{v128.}\LOAD\K{64\_zero}~\memidx~\memarg \\&&|&
     \K{v128.}\LOAD\X{ww}\K{\_splat}~\memidx~\memarg \\&&|&
     \K{v128.}\LOAD\X{ww}\K{\_lane}~\memidx~\memarg~\laneidx ~|~
     \K{i}\X{nn}\K{.}\STORE\K{8}~\memidx~\memarg ~|~
     \K{i}\X{nn}\K{.}\STORE\K{16}~\memidx~\memarg ~|~
     \K{i64.}\STORE\K{32}~\memidx~\memarg \\&&|&
     \K{v128.}\STORE\X{ww}\K{\_lane}~\memidx~\memarg~\laneidx \\&&|&
     \MEMORYSIZE~\memidx \\&&|&
     \MEMORYGROW~\memidx \\&&|&
     \MEMORYFILL~\memidx \\&&|&
     \MEMORYCOPY~\memidx~\memidx \\&&|&
     \MEMORYINIT~\memidx~\dataidx \\&&|&
     \DATADROP~\dataidx \\
   \end{array}

Memory is accessed with |LOAD| and |STORE| instructions for the different :ref:`number types <syntax-numtype>` and :ref:`vector types <syntax-vectype>`.
They all take a :ref:`memory index <syntax-memidx>` and a *memory immediate* |memarg| that contains an address *offset* and the expected *alignment* (expressed as the exponent of a power of 2).

Integer loads and stores can optionally specify a *storage size* that is smaller than the :ref:`bit width <syntax-numtype>` of the respective value type.
In the case of loads, a sign extension mode |sx| is then required to select appropriate behavior.

Vector loads can specify a shape that is half the :ref:`bit width <syntax-valtype>` of |V128|. Each lane is half its usual size, and the sign extension mode |sx| then specifies how the smaller lane is extended to the larger lane.
Alternatively, vector loads can perform a *splat*, such that only a single lane of the specified storage size is loaded, and the result is duplicated to all lanes.

The static address offset is added to the dynamic address operand, yielding a 33-bit or 65-bit *effective address* that is the zero-based index at which the memory is accessed.
All values are read and written in |LittleEndian|_ byte order.
A :ref:`trap <trap>` results if any of the accessed memory bytes lies outside the address range implied by the memory's current size.

The |MEMORYSIZE| instruction returns the current size of a memory.
The |MEMORYGROW| instruction grows a memory by a given delta and returns the previous size, or :math:`-1` if enough memory cannot be allocated.
Both instructions operate in units of :ref:`page size <page-size>`.
The |MEMORYFILL| instruction sets all values in a region of a memory to a given byte.
The |MEMORYCOPY| instruction copies data from a source memory region to a possibly overlapping destination region in another or the same memory; the first index denotes the destination.
The |MEMORYINIT| instruction copies data from a :ref:`passive data segment <syntax-data>` into a memory.
The |DATADROP| instruction prevents further use of a passive data segment. This instruction is intended to be used as an optimization hint. After a data segment is dropped its data can no longer be retrieved, so the memory used by this segment may be freed.

.. index:: ! control instruction, ! structured control, ! exception, ! label, ! block, ! block type, ! branch, result type, label index, function index, type index, tag index, vector, trap, function, table, tag, function type, value type, tag type, try block, catching try block
   pair: abstract syntax; instruction
   pair: abstract syntax; block type
   pair: block; type
.. _syntax-blocktype:
.. _syntax-nop:
.. _syntax-unreachable:
.. _syntax-block:
.. _syntax-loop:
.. _syntax-if:
.. _syntax-br:
.. _syntax-br_if:
.. _syntax-br_table:
.. _syntax-br_on_null:
.. _syntax-br_on_non_null:
.. _syntax-br_on_cast:
.. _syntax-br_on_cast_fail:
.. _syntax-return:
.. _syntax-call:
.. _syntax-call_indirect:
.. _syntax-instr-seq:
.. _syntax-instr-control:
.. _syntax-throw:
.. _syntax-throw_ref:
.. _syntax-try_table:
.. _syntax-catch:
.. _exception:

Control Instructions
~~~~~~~~~~~~~~~~~~~~

Instructions in this group affect the flow of control.

.. math::
   \begin{array}{llrl}
   \production{block type} & \blocktype &::=&
     \typeidx ~|~ \valtype^? \\
   \production{instruction} & \instr &::=&
     \dots \\&&|&
     \NOP \\&&|&
     \UNREACHABLE \\&&|&
     \BLOCK~\blocktype~\instr^\ast~\END \\&&|&
     \LOOP~\blocktype~\instr^\ast~\END \\&&|&
     \IF~\blocktype~\instr^\ast~\ELSE~\instr^\ast~\END \\&&|&
     \BR~\labelidx \\&&|&
     \BRIF~\labelidx \\&&|&
     \BRTABLE~\vec(\labelidx)~\labelidx \\&&|&
     \BRONNULL~\labelidx \\&&|&
     \BRONNONNULL~\labelidx \\&&|&
     \BRONCAST~\labelidx~\reftype~\reftype \\&&|&
     \BRONCASTFAIL~\labelidx~\reftype~\reftype \\&&|&
     \RETURN \\&&|&
     \CALL~\funcidx \\&&|&
     \CALLREF~\typeidx \\&&|&
     \CALLINDIRECT~\tableidx~\typeidx \\&&|&
     \RETURNCALL~\funcidx \\&&|&
     \RETURNCALLREF~\typeidx \\&&|&
     \RETURNCALLINDIRECT~\tableidx~\typeidx \\&&|&
     \THROW~\tagidx \\&&|&
     \THROWREF \\ &&|&
     \TRYTABLE~\blocktype~\catch^\ast~\instr^\ast~\END \\
   \production{catch clause} & \catch &::=&
     \CATCH~\tagidx~\labelidx \\ &&|&
     \CATCHREF~\tagidx~\labelidx \\ &&|&
     \CATCHALL~\labelidx \\ &&|&
     \CATCHALLREF~\labelidx \\
   \end{array}

The |NOP| instruction does nothing.

The |UNREACHABLE| instruction causes an unconditional :ref:`trap <trap>`.

The |BLOCK|, |LOOP|, |IF|, and |TRYTABLE| instructions are *structured* instructions.
They bracket nested sequences of instructions, called *blocks*,
separated by the |ELSE| pseudo-instruction,
and terminated with an |END| pseudo-instruction.
As the grammar prescribes, they must be well-nested.

The instructions |THROW|, |THROWREF|, and |TRYTABLE| are concerned with *exceptions*.
The |TRYTABLE| instruction installs an exception *handler* that handles exceptions as specified by its catch clauses..
The |THROW| and |THROWREF| instructions raise and reraise an exception, respectively, and transfers control to the innermost enclosing exception handler that has a matching catch clause.

A structured instruction can consume *input* and produce *output* on the operand stack according to its annotated *block type*.
It is given either as a :ref:`type index <syntax-funcidx>` that refers to a suitable :ref:`function type <syntax-functype>` reinterpreted as an :ref:`instruction type <syntax-instrtype>`, or as an optional :ref:`value type <syntax-valtype>` inline, which is a shorthand for the instruction type :math:`[] \to [\valtype^?]`.

Each structured control instruction introduces an implicit *label*.
Labels are targets for branch instructions that reference them with :ref:`label indices <syntax-labelidx>`.
Unlike with other :ref:`index spaces <syntax-index>`, indexing of labels is relative by nesting depth,
that is, label :math:`0` refers to the innermost structured control instruction enclosing the referring branch instruction,
while increasing indices refer to those farther out.
Consequently, labels can only be referenced from *within* the associated structured control instruction.
This also implies that branches can only be directed outwards,
"breaking" from the block of the control construct they target.
The exact effect depends on that control construct.
In case of |BLOCK| or |IF| it is a *forward jump*,
resuming execution after the matching |END|.
In case of |LOOP| it is a *backward jump* to the beginning of the loop.

.. note::
   This enforces *structured control flow*.
   Intuitively, a branch targeting a |BLOCK| or |IF| behaves like a :math:`\K{break}` statement in most C-like languages,
   while a branch targeting a |LOOP| behaves like a :math:`\K{continue}` statement.

Branch instructions come in several flavors:
|BR| performs an unconditional branch,
|BRIF| performs a conditional branch,
and |BRTABLE| performs an indirect branch through an operand indexing into the label vector that is an immediate to the instruction, or to a default target if the operand is out of bounds.
The |BRONNULL| and |BRONNONNULL| instructions check whether a reference operand is :ref:`null <syntax-null>` and branch if that is the case or not the case, respectively.
Similarly, |BRONCAST| and |BRONCASTFAIL| attempt a downcast on a reference operand and branch if that succeeds, or fails, respectively.

The |RETURN| instruction is a shortcut for an unconditional branch to the outermost block, which implicitly is the body of the current function.
Taking a branch *unwinds* the operand stack up to the height where the targeted structured control instruction was entered.
However, branches may additionally consume operands themselves, which they push back on the operand stack after unwinding.
Forward branches require operands according to the output of the targeted block's type, i.e., represent the values produced by the terminated block.
Backward branches require operands according to the input of the targeted block's type, i.e., represent the values consumed by the restarted block.

The |CALL| instruction invokes another :ref:`function <syntax-func>`, consuming the necessary arguments from the stack and returning the result values of the call.
The |CALLREF| instruction invokes a function indirectly through a :ref:`function reference <syntax-reftype>` operand.
The |CALLINDIRECT| instruction calls a function indirectly through an operand indexing into a :ref:`table <syntax-table>` that is denoted by a :ref:`table index <syntax-tableidx>` and must contain :ref:`function references <syntax-reftype>`.
Since it may contain functions of heterogeneous type,
the callee is dynamically checked against the :ref:`function type <syntax-functype>` indexed by the instruction's second immediate, and the call is aborted with a :ref:`trap <trap>` if it does not match.

The |RETURNCALL|, |RETURNCALLREF|, and |RETURNCALLINDIRECT| instructions are *tail-call* variants of the previous ones.
That is, they first return from the current function before actually performing the respective call.
It is guaranteed that no sequence of nested calls using only these instructions can cause resource exhaustion due to hitting an :ref:`implementation's limit <impl-exec>` on the number of active calls.


.. index:: ! expression, constant, global, offset, element, data, instruction
   pair: abstract syntax; expression
   single: expression; constant
.. _syntax-expr:

Expressions
~~~~~~~~~~~

:ref:`Function <syntax-func>` bodies, initialization values for :ref:`globals <syntax-global>`, elements and offsets of :ref:`element <syntax-elem>` segments, and offsets of :ref:`data <syntax-data>` segments are given as expressions, which are sequences of :ref:`instructions <syntax-instr>` terminated by an |END| marker.

.. math::
   \begin{array}{llrl}
   \production{expression} & \expr &::=&
     \instr^\ast~\END \\
   \end{array}

In some places, validation :ref:`restricts <valid-constant>` expressions to be *constant*, which limits the set of allowable instructions.
