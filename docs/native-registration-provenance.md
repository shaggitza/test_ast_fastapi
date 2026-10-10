# Native route registration provenance

The secure AST extractor records source ownership for static FastAPI route
assembly. For an imported router, provenance includes the registration edge,
the import used by that edge, and each statically followed project-local
re-export. Effective literal `__all__` entries are recorded at every export
hop, so a change to an intermediate package surface can be mapped to the
descendant routes that consume it. Reassignment, deletion, dynamic mutation,
or a reference that may let the live list escape invalidates stale `__all__`
evidence until a later literal assignment establishes a new value. Reference
checks include nested top-level control-flow statements and remain conservative
when their effects cannot be determined without executing the module.
Destructured and chained assignments do not establish literal export evidence,
because they can bind aliases with later mutation paths.

Export traversal is bounded by the number of indexed modules and a fixed hop
limit, and stops on cycles or bindings that cannot be proven from source. This
is source evidence only: it does not establish that importing the application
would succeed or that runtime framework behavior matches the static model.
Dynamic exports and unresolved bindings remain conditional or unresolved.
