# Analysis coverage and limits

[Project overview](../README.md) · [API reference](api.md) · [Design](design.md)

## Interpreting scan results

For a bounded source helper, PCResolve may prove that a finite set of string
keys can change while all other dictionary entries retain their input origins.
Scan can follow that remaining open space. The affected keys remain incomplete;
`pcresolve_mapping_values_partial` keeps coverage limited. A tuple-returning
helper requires an exact supported slot. An unknown slot, clear, finite rebuild,
escape or unsupported mutation does not regain an open source from object
identity. These structural facts do not establish a selected argument's handling
state in assessment.

A positive finding records an API's variadic container reaching an expansion
into a downstream signature without the corresponding variadic parameter.
`has_vpp` is true when the findings collection is nonempty.

`boundaries` separately records unresolved targets, unsupported effects and
other analysis limits. An empty findings collection means no VPP was detected
within the supported analysis; inspect the boundaries to understand coverage.

`coverage` summarizes findings and recorded limits for each root `*args` or
`**kwargs` channel. Its status is `unavailable` for a root analysis failure,
`limited` when a boundary is recorded, or `no_known_boundary` when none is
recorded. No status certifies complete coverage. A finding and a limitation
can coexist; neither the absence of findings nor the absence of recorded
boundaries proves that no propagation exists.

Channel-specific scan boundaries identify `root_function`, `parameter_name`
and `parameter_kind`, while `function` and `callsite` identify the stopping
point, which may be in a downstream helper. Source-scope failures apply to
all considered channels. Missing source/API entries remain report-level
boundaries without fabricated coverage records.

Findings and forwarding steps retain `target_status`. A source candidate
identifies a potential implementation rather than confirmed runtime dispatch.
Structural findings therefore describe forwarding patterns, not the failure
of every call to that API. A fixed downstream signature may accept a particular
argument name, or the library may consume it before forwarding the remainder.
Use parameter-level assessment to examine that argument under a supplied call.

A public source-class scan can requery PCResolve for a conditional source-state
path when the producer reports `source_lookup_candidate`. Each affected path
step and finding exposes `conditions`: source branch outcomes and required
`source_state_preserved` predicates tied to the original unknown effect.
`conditional_source_candidate` identifies a lookup that depends on that state.
Ordinary paths are retained alongside the additional conditional query.
A requirement is not proof that the effect is harmless or the path is feasible.
The finding describes forwarding if all recorded conditions and normal
continuations hold. Unknown effects/configuration keep coverage `limited`.
Known method/MRO replacement, receiver rebinding, inactive branches and budget
limits do not acquire confirmed lookup from this mode.

For Tornado 3.0, the public `AsyncHTTPClient` source entry can expose a path via
`Configurable.__new__` to `SimpleAsyncHTTPClient.initialize`. It retains the
non-reuse branch, `cls is base`, the default-configuration branch and required
class lookup preservation across the intervening source calls. This does not
select the actual backend, prove cache contents or guarantee that an invocation
reaches initialization. Assessment uses ordinary facts in a separate cache and
retains its independent handling/lifecycle limitations.

## Scan coverage

Supported analysis includes:

- Functions, methods and `async def`.
- Cross-file imports, aliases, public class re-exports and inherited methods.
- Source class entries with PCResolve-proven allocator or ordinary initializer binding.
- Bounded multi-hop forwarding through ordinary mapping or sequence parameters.
- Source-resolved helpers returning a whole container, including selection
  through exact nonnegative tuple return slots.
- Incoming receiver and callable contexts supplied by PCResolve for supported
  exact call edges.
- Proven returned-object aliases and complete finite constant-key removal
  facts that preserve an open remainder.
- Bounded builtin dict copies and dict/list/tuple conversions, when PCResolve
  supplies matching copy effects, object identity and current contents.
- Immediately invoked synchronous source closures with exact call-time captured
  container shapes and current open contents; nested named scopes can relay
  the same capture within the forwarding depth limit.
- Source-selected lambdas, indexed by their lexical owner and exact line/column
  identity. Their expression body is exposed as a return-statement view, without
  compiling or executing it; same-line lambdas remain distinct.

Passing a container as an ordinary argument is a propagation hop, not a
finding by itself. A finding requires an eventual expansion into a signature
without the corresponding variadic parameter. Selected input elements and
finite contents are distinguished from an open variadic container.

### Returns and mutation

For a proven returned-object alias, the scanner uses separately materialized
current contents rather than old input dependencies. Removing modeled finite
keys retains the open remainder; clearing an alias does not restore its
original contents. Object identity alone is insufficient to establish
variadic propagation.

Copy proofs are checked against the producing call, its indexed source witness,
the exact input/output objects and normal-completion effects. The scanner reads
current contents at the expansion; it does not restore a cleared copy from old
input dependencies. Copies can retain an independent open remainder after the
original is cleared. Paths record builtin copy/conversion steps under `builtins`
with `target_status="local_container_protocol"`; each step counts toward depth.
Missing, conflicting or effect-uncertain facts remain boundaries.

Complete ordinary-parameter constant-key removal facts can preserve propagation
through an existing alias. Normal-return effects describe that return path,
rather than unconditional removal on exception paths.
Complete same-module helper effects can also preserve returned-object identity
through bounded finite-key deletion wrappers. Unused direct helper calls must
resolve to stable undecorated functions with fully bound ordinary-name inputs;
unknown keys, shadowed targets, unsupported effects and recursive/budget-limited
composition retain boundaries. This does not infer general helper purity.

### Dispatch and decoration

PCResolve's equality-branch `is` guard facts can select a stable undecorated
source function for variadic forwarding, including the complement branch of
`is not`. The consumer preserves the guard and incoming call context; inequality,
`==`, arbitrary callable predicates and source-unknown attribute lookup do not select
a target. Open/incomplete callable candidate sets remain boundaries after joins.
Explicit callable or immutable scalar arguments are retained during helper
expansion so a known incompatible identity cannot use the generic guarded path.
These facts describe source-conditioned paths, not unconditional runtime targets.

Classmethod and `__new__` helper forwarding retains source-proven incoming
receiver contexts. Ordinary helpers retain incoming source-callable bindings
and source-class argument origins when PCResolve provides an exact call-edge
context. A source class can pass through multiple ordinary helpers to a fixed
classmethod signature only with a matching source binding proof. Both consumers
validate the call target, snapshot hashes and every incoming binding context.
Custom lookup remains unconfirmed even when the class identity is known.
Class writes/deletes and unknown effects on receivers, captures or local
containers invalidate this binding route. A nominal class on a generic method entry does
not establish its actual receiver. Constructor entry binding and mutable runtime
configuration can still stop this route.

Missing or mixed incoming contexts remain boundaries. Mutable configuration
attributes and class-context container returns are not inferred. Callable
targets are not inferred from names or strings. Ambiguous constructor
definitions are not replaced with a guessed entry.

An explicit source class call can carry PCResolve's exact implicit class binding
into a supported synchronous `__new__`. Scan validates its
`constructor_bindings`, invocation phase, snapshot and incoming contexts before
following the body. Deferred allocator bodies remain boundaries. Class/base
escapes, allocator writes, custom lookup, invalid binding and conflicting facts
cannot license that route. The proof supplies no initialized instance state or
later constructor phases, so assessment retains `dynamic_construction` even
when scan has an allocator-body witness. For explicit class calls, PCResolve
selects the MRO allocator before an initializer. An inherited `__new__` therefore
takes precedence over a direct `__init__`. Scan follows only the supported
selected phase: it does not infer an initializer edge from a class identity.
`pcresolve_constructor_initialization_unmodeled` retains the later-phase gap,
including when a source allocator returns an instance that Python initializes.
Class API queries use PCResolve's entry binding to retain the actual class,
including inherited allocators and method overrides. The consumer checks phase,
receiver, MRO, source hashes and implicit parameter before entering the body.
Missing entry facts, custom/deferred allocation and unknown construction remain
resolution boundaries. Generic method queries retain their separate contexts.

Ordinary builtin allocation can instead select a source `__init__` invocation.
Scan requires its matching `constructor_instance` binding and actual incoming
`instance_type`, including when the initializer is inherited. It expands that
call edge and rejects missing/conflicting receiver contexts. This proves one
invocation phase under source snapshot assumptions; initialized state and
complete construction effects remain unmodeled. Unknown receiver effects,
custom attribute lookup and changed source members retain lookup boundaries.

When a decorated callable has a proven identity but unmodeled effects, the
scanner does not use its body to prove container returns or further
forwarding. A direct expansion against its nominal signature can still produce
a structural finding, retaining the effects diagnostic.

### Unresolved propagation

Unknown effects on returned containers and transformations without open-shape
facts remain boundaries. Examples include comprehensions, copies and slices
when the required shape facts are unavailable.

Carrier receiver operations preserve PCResolve's specific effect diagnostics
even when no ordinary argument flow was produced. Locally resolved callables
with captured channel dependencies report `closure_capture_not_followed` when
their current capture facts, synchronous execution or unique call context
cannot be established. Proven immediate captures are followed using isolated
edge expansion, retaining call-time rebinding and modeled mutations. Generator
and async callable bodies are not inferred to execute merely from a call.
Unmodeled writes or effects retain boundaries;
returned local callables with lexical captures report
`deferred_callable_not_followed`. These diagnostics describe unmodeled
propagation, not newly established forwarding paths. Lexical capture does
not prove the current captured value, and returned-callable execution is
outside the immediate scan path. Shadowed local parameters are not captures.

Unresolved targets, unsupported propagation, recursion and depth limits also
remain visible diagnostics. The default depth limit is five hops;
source-resolved return-producing calls count toward the limit.

Recorded flow conditions contradicted by matching constant source syntax are
excluded from findings, including literal truth values, `not` and decisive
`and`/`or` expressions. Other conditions remain potential paths. This does not
solve general path feasibility, infer caller values or change a structural
finding into a parameter-level compatibility decision.
If joined contents cannot be separated from an impossible object context,
the scanner retains `return_object_unproven` rather than treating the object's
materialized input dependencies as independent propagation.

## Source-scope boundaries

Module names follow the source context's import roots. File/name/line conflicts
and unavailable implementations remain unresolved rather than guessed.
Definitions in conditional statement blocks, including class methods in an
exception handler, retain their lexical source identity. PCResolve records
`conditional_definition_unconfirmed` with activation conditions; a located
entry does not prove the branch is active at runtime. Duplicate conditional
names require an exact location, and constant-inactive definition conditions
cannot supply a forwarding path.

API-scoped preparation follows explicit imports within the source root.
Dynamic dependencies are not inferred, so an import closure describes a
bounded source scope rather than complete runtime coverage.

Reuse an analysis context only within its fixed file set and unchanged source
snapshot. An API-scoped context cannot be used for whole-package scanning.
See [source identities and contexts](api.md#source-identities-and-contexts)
for scope selection and context construction.

## Assessment states

Each assessment describes one selected changed argument under the supplied
call conditions and any recorded normal-path preconditions.

| State | Meaning |
| --- | --- |
| `HANDLED` | The argument's value or presence is used, or its value binds to a downstream explicit parameter. |
| `REJECTED` | Supported conditions lead to a parameter-specific binding rejection or an explicit captured-key rejection. |
| `IGNORED` | Supported executed paths do not use the argument's value or presence. |
| `NOT_ENTERED` | An unrelated binding error in the original call prevents entry into the requested source implementation. The selected argument receives no use/rejection verdict. |
| `UNKNOWN` | Binding, control flow, dispatch or effects prevent a definite result. |

These are argument-handling states. Behavioral equivalence between library
versions and code modification are outside this analysis. In particular,
unused arguments and unresolved analysis do not establish that a deletion or
rename is safe, and rejection evidence does not establish that a proposed
modification succeeds.

`NOT_ENTERED` applies only to a proved entry-signature failure of an undecorated
implementation, after parameter-specific rejection checks. It does not apply to
unresolved expansions, uncertain decorator binding, or a later callee failure.
It records `entry_binding_failed` evidence and never permits deleting the selected
argument. The distinction lets callers report a definite invalid original call
without treating it as either successful parameter handling or analysis unknown.

A supported, completed value/presence consumption can remain positive handling
evidence across a later unsupported mapping effect or call, only after no raw
selected value remains in any active frame, container or pending call argument.
A validated exact scalar conversion can establish that distinction. Such a result retains
the later boundary and uses `proven_consumption_before_boundary`; it does not
claim successful completion or absence of later failures. An explicit
parameter-specific rejection proved before analysis stops still takes
precedence. Merely removing an optional key or calculating an unused value
does not establish this consumption witness.

### Assessment coverage

Current assessment covers changed keywords captured by `**kwargs` and selected
positional elements captured by `*args`, regardless of the container's name.
Supported cases include direct/alias forwarding, finite expansions, bounded
`pop` effects, simple literal/default-value guards and source-resolved
downstream binding.

Finite string-key dictionary displays can merge known mappings. Later keys
overwrite earlier values, while duplicate keys in a call's keyword expansions
retain Python's binding rejection. Unknown mappings remain unresolved. Passing
the resulting carrier as an ordinary dictionary parameter does not by itself
prove that a downstream validator accepts its contents.

Finite dictionaries and sequences can pass through ordinary helper parameters
when the call target and exact parameter binding are supported by PCResolve.
Assessment follows the helper body with the same selected contents and depth
budget; merely accepting the container is not acceptance of its contents.
Unresolved callable-instance candidates and dynamic override boundaries are
not promoted to confirmed targets.

Assessment preserves selected contents through `dict(mapping)`, `tuple(sequence)`
and `list(sequence)` when PCResolve proves the matching builtin copy protocol.
Dictionary copies keep independent key removal; sequence copies retain element
order and list/tuple kind. The source witness and copy effects must agree;
custom containers, constructor rebinding and unknown mutation remain unresolved.

Immediately called local source functions can receive exact call-time captured
dictionaries and sequences. Each call uses current modeled contents and shares
container aliases with its enclosing frame; nested calls consume the existing
depth budget. The selected argument can continue through a returned container.
Scalar/unknown captures, escaped or rebound local callables, nonlocal writes,
definition-time calls and deferred async/generator execution remain unresolved.
Captured slices without exact container facts are not inferred from lexical use.

For finite string-key dictionaries, assessment supports unshadowed built-in
`set(mapping)`, key-set difference and singleton `list(keys)` projection.
The selected key is tracked separately from other keys. An established
key-presence rejection branch can report `proven_guard_rejection` for a built-in
exception constructed from finite primitive arguments or a simple finite
formatted message. Unknown keys, ambiguous set iteration order, shadowed
protocols, exception recovery and arbitrary value-constraint failures remain
unresolved. Disjunctions and rejection in the opposite branch are outside this
narrow proof. A shallow dictionary copy requires a matching bounded PCResolve
copy fact; other mutations still require their own effect evidence.

For a single decorated entry/body, an exact PCResolve `decorator_effects` fact
can permit analysis of the original body when both identity and body/binding
are preserved. The fact must match the source definition, decoration span and
source hashes, with no unresolved or conflicting effects. Its normal-completion
scope and source assumptions are recorded as `source_decorator_binding`
evidence. Identity alone, missing facts, code/default changes and unsupported
decorator composition remain unresolved; independent call boundaries still apply.

A closed proof may include source-helper calls, documentation-cache construction,
conditional `setdefault` effects and mapping lookups alongside `__doc__` writes.
These records support the overall preservation proof; they do not independently
prove that a helper or cache is harmless. Partial records in an unresolved proof
do not permit body analysis, and input-function writes other than `__doc__`
remain unsupported.

A closed decoration proof can also include scalar field updates on a
single-decoration instance and builtin `str.join` over a finite string list or
tuple. Shared-instance state, conditional/unknown writes and custom iterable
protocols are not admitted. These supporting data effects cannot override a
remaining unresolved helper call, even when its arguments are documentation
strings; no decorator or document-processing library name is a transparency rule.

Finite `str.split` and restricted `str.format` records are accepted only inside
that same complete source decoration proof. The consumer validates their string
operand shapes, normal-completion scope and explicit field/separator restrictions.
This permits source-proved documentation factories without executing them.
Independent entry-body control flow remains subject to ordinary assessment rules.

An assertion whose finite test is definitely true and independent of the selected
argument can retain its continuation without evaluating its error message. This
continuation is the same with assertions enabled or disabled. False, unknown or
selected-argument-dependent assertion execution stays unresolved; it does not
establish a rejection. Equality with an empty known builtin keyword dictionary
can be decided without comparing payloads. A finite `and`/`or` tree of local
`is None` / `is not None` probes can also join unknown identity outcomes when all
outcomes give the same final Boolean. Calls, attributes, custom truth protocols
and other comparisons do not acquire this branch proof.

An exact PCResolve `builtin_container_length` obligation permits `len` over a
finite builtin capture/container or a known primitive string/bytes value.
The consumer checks the builtin target, call binding, source span/hash and every
input/completion/effect condition. Unknown objects and shadowed targets remain
unresolved. Length results preserve selected-element presence independently of
payload values; a discarded length does not itself imply consumption.

Finite builtin tuple/list values can be unpacked into a matching tree of ordinary
local names. Unknown iterables, mismatched lengths, starred targets and attribute
destinations do not gain a binding proof. Membership in a finite tuple/list is
evaluated only for known primitive operands, without invoking application equality.
Exact unpacking of a variadic capture also consumes element presence through its
arity requirement, including when that element's eventual payload is discarded.
After a completed parameter-use witness, an unrelated unpack into ordinary local
names can join its failure path with a checked continuation using unknown locals.
That failure cannot undo the earlier use. The possible early termination remains
recorded across helper returns: a rejection found only in the continuation stays
UNKNOWN. Unproved unpacking before parameter use, or unpacking that involves the
selected argument, still stops analysis.

A function-local from-import may continue under a matching PCResolve
`source_cached_import_binding` fact. This requires prior unconditional source
initialization of the imported module, a unique source export, ordinary module
lookup, matching initialization/import evidence and hashes. The evidence retains
the standard import, preserved source-module cache/namespace and no external
import-hook or indirect mutation premises. Imported names replace prior local
bindings and invalidate matching supplied facts. New, relative or unproved
imports retain `local_import_execution_unconfirmed`; arbitrary module execution
is not inferred harmless, and runtime import success is not established.

Finite guards support `isinstance()` against unshadowed built-in `str`, `bytes`,
`int`, `float`, `bool` and `object` types, and `startswith()` / `endswith()` on
known strings with one known string argument. Unknown values, shadowed built-ins
and unsupported predicate arguments remain unresolved; source code is not run.

Positional assessment preserves finite sequence order through constant indices,
slices, same-kind concatenation and expansion. Rejection requires the selected
value to reach a slot beyond a callee's positional capacity or another supported
parameter-specific binding conflict. An error caused only by another supplied
element does not license rejecting the selected one. Unknown-length expansions,
sequence unpacking, unproven ordinary-container calls and unsupported mutations
remain boundaries rather than assumptions about argument acceptance.

### Normal-path preconditions

An unknown simple guard that only raises an unrelated exception need not stop
parameter analysis. The analyzer records a `normal_path_precondition` in
`evidence` and continues along the normal path, without assigning a value to
the guard or the receiver attribute. This applies only to supported plain
reads, a single unshadowed built-in exception construction with constant
arguments, and an empty or `pass`-only alternative branch.

An available guard value still selects the actual supported branch. Parameter
consumption, early returns, exception recovery, calls in the condition or
message, and source-known custom receiver getters are not bypassed. Results
with preconditions describe argument handling on the normal path, not proof
that a particular invocation reaches it.

Exception recovery, unknown mutation, deferred execution and unsupported
transformations remain explicit boundaries. An absent selected argument or one
not captured by the target's corresponding variadic parameter also yields an
unresolved assessment.

PCResolve may establish a closed `mapping_key_accesses` footprint for a
`**kwargs` capture. If all tracked elements have keys outside that footprint,
assessment can establish `unread_mapping_element` without interpreting unrelated
loops or branches. Only fixed string-key subscriptions, membership and `get`
accesses and fixed-key `pop` calls are covered. Whole-container forwarding,
aliases, non-key-local mutation, dynamic
keys, nested capture and visible namespace/frame inspection prevent this proof.
It assumes no external frame introspection and establishes element non-use,
not that the function reaches a return or the original call succeeds. Decorator,
entry binding and source snapshot checks still apply. Scan is unchanged.

### Supplied call facts

`CallContext.observed_fixed_bindings` confirms consumption by an actual fixed
method parameter when runtime factory/dispatch choices are otherwise unresolved.
The caller independently confirms that this original invocation's selected
primitive reaches the recorded exact builtin mapping, that one source call
expands it into the actual bound method, that the method frame enters with this
same primitive in its fixed formal, and that the original invocation completes
normally, including all constructor phases when applicable. Assess matches the
original call/entry, key/value, source caller and call span, expansion variable,
target method, fixed keyword-capable parameter and source hashes. PCResolve's
neutral call record and target parameter summary must match source AST and
snapshot. Only an undecorated bound method reached by one `**name` expansion is
covered. Missing/conflicting evidence keeps `unknown`. This observation-assisted
`handled` result records fixed binding acceptance; it is not a general factory,
heap, compatibility or later-body-consumption proof. It describes the observed
invocation, so another invocation with a reused factory cache needs its own
evidence. VPPDetector does not collect/authenticate these observations or alter
scan/source caches; only one observation family is accepted per assessment.

`CallContext.observed_capture_rejections` supports source guards that reject
a nonempty dictionary directly or as the final operand of a completed `and`
condition. The caller confirms the actual checker dictionary contains the
selected original primitive, exact builtin type, true guard completion and the
same uncaught exception at the recorded raise. Assess requires a matching
PCResolve `capture_rejection_guards` obligation and verifies source structure,
entry, original call, key/value, parameter, guard/raise spans, builtin exception
kind and source hashes. Only direct `TypeError`/`ValueError` raises with constant
messages are supported. Missing/conflicting evidence keeps `unknown`.
This is observation-assisted rejection of the captured key; it proves neither
unassisted path feasibility nor that removing the key repairs the full client.
Observation families cannot be mixed; observations are trusted caller input
and do not affect scan or source caches.

`CallContext.observed_attribute_retentions` can establish observation-assisted
`handled` when an original constructor capture survives in the returned
instance's ordinary attribute state. The caller must independently confirm
`type.__call__`, default `object.__new__`, ordinary object attribute access and
store, the original receiver's identity as the returned instance, execution of
the recorded assignment and normal class-call completion. The retained object
must be the same exact builtin capture dictionary with the same selected
primitive. Assess also checks PCResolve's neutral direct-store obligation,
source assignment, original call, entry, value and hashes. Missing/conflicting
evidence remains `unknown`. This proves retained state, not that a later method
reads it or that the old and new APIs are compatible. Observation families
cannot be mixed. VPPDetector neither runs nor authenticates these observations;
source caches and scan remain unchanged.

`CallContext.observed_container_predicates` accepts trusted evidence of an actual
completed predicate on a builtin dictionary or tuple containing the selected
original element. Supported source predicates are container truth, string-key
membership and an unshadowed builtin `len` compared with an integer. Only the
definitely evaluated first operand of a Boolean expression is covered. Entry,
original call, selected key or positional index, checker, source spans, hashes,
container size and observed outcome must match PCResolve's neutral
`requires_observation` obligations. The caller must independently establish
element provenance, exact builtin type and normal completion of the original
entry invocation. Tuples require index-preserving provenance. This yields
observation-assisted `handled` for presence/structure consumption; it does not
assert numeric influence on a result or compatibility. Conflicting observation
families are rejected, missing evidence keeps `unknown`, and an assessment
without observations remains independent. The library does not collect or
authenticate these observations, execute client expressions or load object
graphs. Scan is unchanged.

`CallContext.observed_normal_returns` accepts bounded `ObservedNormalReturn`
attestations that the original call reached the identified source frame with the
same captured primitive and returned an exact builtin dictionary normally at the
recorded source span. The consumer additionally requires PCResolve's conditional
`mapping_return_transfers` fact: an update into a fresh dictionary, a matching
return path and no later access to the selected key's field. Whole-map escape,
rebinding, unknown paths and overwritten fields prevent this retention proof.
The call text, source hashes, parameter, return location and producer witnesses
must agree. Missing or conflicting evidence keeps UNKNOWN. This combines static
retention with independent completion evidence; it is an observation-assisted
HANDLED result, and never a compatibility verdict. VPPDetector does not run the
client or collect/authenticate these trusted caller observations. Scan is unchanged.

`CallContext.known_conditions` accepts trusted Boolean predicate outcomes at
exact source spans. It applies only to conditions independent of the selected
argument and cannot override a contradicting computed outcome. The supplied
facts apply to this assessment; scan and producer caches are unaffected.

An independently confirmed `known_targets` location with no producer target
can support a source-signature rejection. An accepted signature still leaves
body binding/effects unresolved. This mode never turns a nominal candidate
into an independent target observation.

`CallContext.observed_keyword_checks` accepts explicit `ObservedKeywordCheck`
records from an uncaught original-call trace. The caller attests that the
indexed entry and the reached mapping validator received the same selected
primitive value, and records the lookup value and escaping exception. Assess
matches the original call, entry/checker, key/lookup slots, attribute template,
raise span, unchanged source hashes and a PCResolve `requires_observation`
guard. A matched `None` lookup followed by the recorded `AttributeError` yields
`observed_keyword_validation_rejection`. Missing or conflicting records remain
unknown. The library neither executes the client nor collects/authenticates
these caller-supplied observations. This is an observation-assisted result,
not an improvement in unaided static recall or proof about other invocations.

Additional facts must describe the supplied call and source version. A nominal
PCResolve candidate does not independently confirm a runtime target; uncertain
class dispatch remains `UNKNOWN` without supporting binding evidence.

For a built-in classmethod, a PCResolve `source_bound` fact can establish static
signature binding under its source-snapshot assumptions. The target, implicit
receiver and all incoming analysis contexts must agree, with no binding issues
or remaining dispatch uncertainty. The assessment records those assumptions as
`source_classmethod_binding` evidence; this is not runtime target confirmation.
Visible rebinding, incomplete mutation analysis and conflicting contexts remain
unresolved. This does not authorize bypassing decorated helper bodies.

A directly constructed module-level callable can be assessed when PCResolve
supplies a matching `source_bound` callable-instance binding and finite
constructor state. The target, receiver, source definition, snapshot hashes,
assumption boundaries and incoming contexts must agree. The assessment records
`source_callable_instance_binding`; it does not confirm runtime dispatch.
Custom construction/lookup, visible writes, escapes and incomplete state retain
uncertainty. Known constructor attributes can select finite conditional
expressions, but unproved writes or untracked helper effects on that state stop
assessment. An exact ordinary dict binding can support a bounded copy before
unproved prior uses; it does not generally enable ordinary-container mutation.

The analyzer does not execute client argument expressions or load runtime
object graphs. Context caches retain program facts, while each assessment
uses its own call conditions.
