import { StringEnum } from "@earendil-works/pi-ai";
import { Type, type Static } from "typebox";

const strict = { additionalProperties: false } as const;
const NonEmpty = Type.String({ minLength: 1, maxLength: 2_000 });
const SafePath = Type.String({
  minLength: 1,
  maxLength: 1_000,
  pattern: "^(?!/)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*\\\\)(?!.*\\u0000).+$",
});

export const DraftLocationSchema = Type.Object(
  {
    side: StringEnum(["baseline", "target"] as const),
    path: SafePath,
    start_line: Type.Integer({ minimum: 1, maximum: 10_000_000 }),
    end_line: Type.Integer({ minimum: 1, maximum: 10_000_000 }),
    symbol: Type.String({ minLength: 1, maxLength: 500 }),
  },
  strict,
);

export const DraftChangedSymbolSchema = Type.Object(
  {
    canonical_name: NonEmpty,
    location: DraftLocationSchema,
  },
  strict,
);

export const DraftEdgeSchema = Type.Object(
  {
    relation: StringEnum(
      ["direct", "calls", "imports", "registers", "dispatches", "depends_on"] as const,
    ),
    from_location: DraftLocationSchema,
    to_location: DraftLocationSchema,
  },
  strict,
);

export const DraftEntrypointSchema = Type.Object(
  {
    public_id: NonEmpty,
    kind: StringEnum(["http", "graphql", "task", "event", "cli", "cron", "sdk", "other"] as const),
    confidence: StringEnum(["confirmed", "probable", "possible"] as const),
  },
  strict,
);

export const DraftClaimSchema = Type.Object(
  {
    recommendation: StringEnum(["include", "exclude", "unknown"] as const),
    summary: NonEmpty,
    entrypoint: DraftEntrypointSchema,
    evidence: Type.Array(DraftEdgeSchema, { minItems: 1, maxItems: 1_000 }),
  },
  strict,
);

export const DraftUnknownSchema = Type.Object(
  {
    category: NonEmpty,
    description: NonEmpty,
    evidence_limit: NonEmpty,
  },
  strict,
);

export const NegativeAssessmentSchema = Type.Object(
  {
    changed_symbol_census_complete: Type.Literal(true),
    searched_entrypoint_families: Type.Array(NonEmpty, { minItems: 1, maxItems: 100 }),
    limitations: Type.Array(NonEmpty, { minItems: 1, maxItems: 100 }),
  },
  strict,
);

/** Provider-facing semantic draft. Identity, hashes, OIDs, IDs and ordinals are absent by design. */
export const ReviewDraftSchema = Type.Object(
  {
    terminal_recommendation: StringEnum(
      ["positive", "negative_control", "unknown", "not_evaluable"] as const,
    ),
    changed_symbols: Type.Array(DraftChangedSymbolSchema, { maxItems: 1_000 }),
    claims: Type.Array(DraftClaimSchema, { maxItems: 1_000 }),
    unknowns: Type.Array(DraftUnknownSchema, { maxItems: 1_000 }),
    negative_assessment: Type.Union([NegativeAssessmentSchema, Type.Null()]),
    notes: Type.String({ maxLength: 20_000 }),
  },
  strict,
);

export type ReviewDraftInput = Static<typeof ReviewDraftSchema>;
