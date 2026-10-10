# Analysis coverage and limits

[Project overview](../README.md) · [API reference](api.md) · [Design](design.md)

## Interpreting scan results

A positive finding records an API's variadic container reaching an expansion
into a downstream signature without the corresponding variadic parameter.
`has_vpp` is true when the findings collection is nonempty.

`boundaries` separately records unresolved targets, unsupported effects and
other analysis limits. An empty findings collection means no VPP was detected
within the supported analysis; inspect the boundaries to understand coverage.

Findings and forwarding steps retain `target_status`. A source candidate
identifies a potential implementation rather than confirmed runtime dispatch.
Structural findings therefore describe forwarding patterns, not the failure
of every call to that API. A fixed downstream signature may accept a particular
argument name, or the library may consume it before forwarding the remainder.
Use parameter-level assessment to examine that argument under a supplied call.

## Scan coverage

Supported analysis includes:

- Functions, methods and `async def`.
- Cross-file imports, aliases, public class re-exports and inherited methods.
- Source constructor entries using `__init__`, otherwise `__new__`.
- Bounded multi-hop forwarding through ordinary mapping or sequence parameters.
- Source-resolved helpers returning a whole container, including selection
  through exact nonnegative tuple return slots.
- Incoming receiver and callable contexts supplied by PCResolve for supported
  exact call edges.
- Proven returned-object aliases and complete finite constant-key removal
  facts that preserve an open remainder.

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

Complete ordinary-parameter constant-key removal facts can preserve propagation
through an existing alias. Normal-return effects describe that return path,
rather than unconditional removal on exception paths.

### Dispatch and decoration

Classmethod and `__new__` helper forwarding retains source-proven incoming
receiver contexts. Ordinary helpers retain incoming source-callable bindings
when PCResolve provides an exact call-edge context.

Missing or mixed incoming contexts remain boundaries. Mutable configuration
attributes and class-context container returns are not inferred. Callable
targets are not inferred from names or strings. Ambiguous constructor
definitions are not replaced with a guessed entry.

When a decorated callable has a proven identity but unmodeled effects, the
scanner does not use its body to prove container returns or further
forwarding. A direct expansion against its nominal signature can still produce
a structural finding, retaining the effects diagnostic.

### Unresolved propagation

Unknown effects on returned containers and transformations without open-shape
facts remain boundaries. Examples include comprehensions, copies and slices
when the required shape facts are unavailable.

Unresolved targets, unsupported propagation, recursion and depth limits also
remain visible diagnostics. The default depth limit is five hops;
source-resolved return-producing calls count toward the limit.

## Source-scope boundaries

Module names follow the source context's import roots. File/name/line conflicts
and unavailable implementations remain unresolved rather than guessed.

API-scoped preparation follows explicit imports within the source root.
Dynamic dependencies are not inferred, so an import closure describes a
bounded source scope rather than complete runtime coverage.

Reuse an analysis context only within its fixed file set and unchanged source
snapshot. An API-scoped context cannot be used for whole-package scanning.
See [source identities and contexts](api.md#source-identities-and-contexts)
for scope selection and context construction.

## Assessment states

Each assessment describes one selected changed argument under the supplied
call conditions.

| State | Meaning |
| --- | --- |
| `HANDLED` | The argument's value or presence is used, or its value binds to a downstream explicit parameter. |
| `REJECTED` | Supported call conditions lead to a parameter-specific binding rejection. |
| `IGNORED` | Supported executed paths do not use the argument's value or presence. |
| `UNKNOWN` | Binding, control flow, dispatch or effects prevent a definite result. |

These are argument-handling states. Behavioral equivalence between library
versions and code modification are outside this analysis. In particular,
unused arguments and unresolved analysis do not establish that a deletion or
rename is safe, and rejection evidence does not establish that a proposed
modification succeeds.

### Assessment coverage

Current assessment covers changed keywords captured by `**kwargs`, regardless
of the container's name. Supported cases include direct/alias forwarding,
finite expansions, bounded `pop` effects, simple literal/default-value guards
and source-resolved downstream binding.

Positional-element propagation, exception recovery, unknown mutation, deferred
execution and unsupported transformations remain explicit boundaries.
An absent selected keyword or a keyword not captured by the target's variadic
parameter also yields an unresolved assessment.

### Supplied call facts

Additional facts must describe the supplied call and source version. A nominal
PCResolve candidate does not independently confirm a runtime target; uncertain
class dispatch remains `UNKNOWN` without independent evidence.

The analyzer does not execute client argument expressions or load runtime
object graphs. Context caches retain program facts, while each assessment
uses its own call conditions.
