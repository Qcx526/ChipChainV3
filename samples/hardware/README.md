# Hardware input workspace

Use this Git-ignored directory for local hardware research inputs such as RTL sources, traces, simulator logs or future SI artifacts. The current controlled Type-II CLI does not parse arbitrary raw hardware files; it consumes an existing canonical hardware behavior contract and provenance-bound run artifacts through an explicit manifest.

Keep real inputs out of `examples/`. Artifact paths may refer to external read-only locations; this directory is a convention, not a domain restriction.
