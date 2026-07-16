PRAGMA foreign_keys = ON;

CREATE TABLE schema_migration(
  version INTEGER PRIMARY KEY CHECK(version > 0),
  name TEXT NOT NULL UNIQUE CHECK(length(name) > 0),
  sha256 TEXT NOT NULL UNIQUE CHECK(sha256 GLOB 'sha256:[0-9a-f]*' AND length(sha256)=71),
  applied_at TEXT NOT NULL CHECK(applied_at GLOB '*Z')
) STRICT;
CREATE TABLE corpus(
  corpus_id TEXT PRIMARY KEY CHECK(length(corpus_id)>0),
  lock_sha256 TEXT NOT NULL UNIQUE CHECK(lock_sha256 GLOB 'sha256:[0-9a-f]*' AND length(lock_sha256)=71),
  schema_version INTEGER NOT NULL CHECK(schema_version=2),
  selected_count INTEGER NOT NULL CHECK(selected_count>=0)
) STRICT;
CREATE TABLE repository(
  repository_id TEXT PRIMARY KEY,
  corpus_id TEXT NOT NULL REFERENCES corpus(corpus_id),
  full_name TEXT NOT NULL, full_name_casefold TEXT NOT NULL,
  partition_name TEXT NOT NULL,
  terminal_status TEXT NOT NULL CHECK(terminal_status IN ('complete','underfilled','unavailable')),
  UNIQUE(corpus_id,full_name_casefold), UNIQUE(repository_id,corpus_id)
) STRICT;
CREATE TABLE pull_request(
  pr_id TEXT PRIMARY KEY,
  repository_id TEXT NOT NULL,
  corpus_id TEXT NOT NULL,
  number INTEGER NOT NULL CHECK(number>0), rank INTEGER NOT NULL CHECK(rank>0),
  merged_at TEXT NOT NULL CHECK(merged_at GLOB '*Z'),
  base_sha TEXT NOT NULL CHECK(length(base_sha)=40),
  head_sha TEXT NOT NULL CHECK(length(head_sha)=40),
  merge_commit_sha TEXT NOT NULL CHECK(length(merge_commit_sha)=40),
  FOREIGN KEY(repository_id,corpus_id) REFERENCES repository(repository_id,corpus_id),
  UNIQUE(repository_id,number), UNIQUE(repository_id,rank), UNIQUE(pr_id,corpus_id)
) STRICT;
CREATE TABLE snapshot(
  snapshot_id TEXT PRIMARY KEY,
  pr_id TEXT NOT NULL REFERENCES pull_request(pr_id),
  side TEXT NOT NULL CHECK(side IN ('baseline','target')),
  commit_sha TEXT NOT NULL CHECK(length(commit_sha)=40),
  tree_sha TEXT NOT NULL CHECK(length(tree_sha)=40), rule TEXT NOT NULL CHECK(length(rule)>0),
  UNIQUE(pr_id,side), UNIQUE(snapshot_id,pr_id,side), UNIQUE(snapshot_id,pr_id)
) STRICT;
CREATE TABLE remote_diff(
  diff_id TEXT PRIMARY KEY, pr_id TEXT NOT NULL UNIQUE REFERENCES pull_request(pr_id),
  sha256 TEXT NOT NULL CHECK(length(sha256)=71), byte_count INTEGER NOT NULL CHECK(byte_count>=0),
  final_url TEXT NOT NULL CHECK(length(final_url)>0), content_type TEXT NOT NULL CHECK(length(content_type)>0),
  baseline_snapshot_id TEXT NOT NULL, baseline_side TEXT NOT NULL CHECK(baseline_side='baseline'),
  target_snapshot_id TEXT NOT NULL, target_side TEXT NOT NULL CHECK(target_side='target'),
  FOREIGN KEY(baseline_snapshot_id,pr_id,baseline_side) REFERENCES snapshot(snapshot_id,pr_id,side),
  FOREIGN KEY(target_snapshot_id,pr_id,target_side) REFERENCES snapshot(snapshot_id,pr_id,side)
) STRICT;
CREATE TABLE import_batch(
  batch_id TEXT PRIMARY KEY,
  artifact_kind TEXT NOT NULL CHECK(artifact_kind IN ('reviews','adjudications')),
  input_root_sha256 TEXT NOT NULL UNIQUE CHECK(length(input_root_sha256)=71),
  imported_at TEXT NOT NULL CHECK(imported_at GLOB '*Z'), importer_sha256 TEXT NOT NULL CHECK(length(importer_sha256)=71),
  bounds_json TEXT NOT NULL CHECK(json_valid(bounds_json))
) STRICT;
CREATE TABLE evidence_location(
  location_id TEXT PRIMARY KEY, pr_id TEXT NOT NULL REFERENCES pull_request(pr_id),
  snapshot_id TEXT NOT NULL, blob_sha TEXT NOT NULL CHECK(length(blob_sha)=40),
  path TEXT NOT NULL CHECK(length(path)>0), start_line INTEGER NOT NULL CHECK(start_line>0),
  end_line INTEGER NOT NULL CHECK(end_line>=start_line), symbol TEXT NOT NULL CHECK(length(symbol)>0),
  FOREIGN KEY(snapshot_id,pr_id) REFERENCES snapshot(snapshot_id,pr_id),
  UNIQUE(snapshot_id,blob_sha,path,start_line,end_line,symbol), UNIQUE(location_id,pr_id)
) STRICT;
CREATE TABLE reviewer_run(
  run_id TEXT PRIMARY KEY, pr_id TEXT NOT NULL REFERENCES pull_request(pr_id),
  lane TEXT NOT NULL CHECK(lane IN ('A','B')), artifact_sha256 TEXT NOT NULL UNIQUE CHECK(length(artifact_sha256)=71),
  artifact_bytes BLOB NOT NULL, reviewer_kind TEXT NOT NULL CHECK(reviewer_kind IN ('human','agent')),
  reviewer_name TEXT NOT NULL, reviewer_version TEXT NOT NULL,
  prompt_sha256 TEXT NOT NULL CHECK(length(prompt_sha256)=71), model_policy_sha256 TEXT NOT NULL CHECK(length(model_policy_sha256)=71),
  tool_policy_sha256 TEXT NOT NULL CHECK(length(tool_policy_sha256)=71), source_policy_sha256 TEXT NOT NULL CHECK(length(source_policy_sha256)=71),
  started_at TEXT NOT NULL, completed_at TEXT NOT NULL,
  terminal_recommendation TEXT NOT NULL CHECK(terminal_recommendation IN ('positive','negative_control','unknown','not_evaluable')),
  import_batch_id TEXT NOT NULL REFERENCES import_batch(batch_id),
  UNIQUE(pr_id,lane), UNIQUE(run_id,pr_id), UNIQUE(run_id,pr_id,lane)
) STRICT;
CREATE TABLE review_changed_symbol(
  changed_symbol_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, pr_id TEXT NOT NULL,
  local_symbol_id TEXT NOT NULL, canonical_name TEXT NOT NULL, location_id TEXT NOT NULL,
  FOREIGN KEY(run_id,pr_id) REFERENCES reviewer_run(run_id,pr_id),
  FOREIGN KEY(location_id,pr_id) REFERENCES evidence_location(location_id,pr_id),
  UNIQUE(run_id,local_symbol_id)
) STRICT;
CREATE TABLE review_claim(
  claim_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, pr_id TEXT NOT NULL,
  local_claim_id TEXT NOT NULL, recommendation TEXT NOT NULL CHECK(recommendation IN ('include','exclude','unknown')),
  summary TEXT NOT NULL, FOREIGN KEY(run_id,pr_id) REFERENCES reviewer_run(run_id,pr_id),
  UNIQUE(run_id,local_claim_id), UNIQUE(claim_id,pr_id)
) STRICT;
CREATE TABLE review_entrypoint(
  entrypoint_id TEXT PRIMARY KEY, claim_id TEXT NOT NULL UNIQUE REFERENCES review_claim(claim_id),
  public_id TEXT NOT NULL, kind TEXT NOT NULL, confidence TEXT NOT NULL
) STRICT;
CREATE TABLE review_evidence_edge(
  edge_id TEXT PRIMARY KEY, claim_id TEXT NOT NULL, pr_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL CHECK(ordinal>=0), relation TEXT NOT NULL,
  from_location_id TEXT NOT NULL, to_location_id TEXT NOT NULL,
  FOREIGN KEY(claim_id,pr_id) REFERENCES review_claim(claim_id,pr_id),
  FOREIGN KEY(from_location_id,pr_id) REFERENCES evidence_location(location_id,pr_id),
  FOREIGN KEY(to_location_id,pr_id) REFERENCES evidence_location(location_id,pr_id),
  UNIQUE(claim_id,ordinal)
) STRICT;
CREATE TABLE review_unknown(
  unknown_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, pr_id TEXT NOT NULL,
  local_unknown_id TEXT NOT NULL, category TEXT NOT NULL, description TEXT NOT NULL, evidence_limit TEXT NOT NULL,
  FOREIGN KEY(run_id,pr_id) REFERENCES reviewer_run(run_id,pr_id),
  UNIQUE(run_id,local_unknown_id), UNIQUE(unknown_id,pr_id)
) STRICT;
CREATE TABLE review_negative_assessment(
  run_id TEXT PRIMARY KEY, pr_id TEXT NOT NULL,
  changed_symbol_census_complete INTEGER NOT NULL CHECK(changed_symbol_census_complete=1),
  searched_families_json TEXT NOT NULL CHECK(json_valid(searched_families_json)),
  limitations_json TEXT NOT NULL CHECK(json_valid(limitations_json)),
  FOREIGN KEY(run_id,pr_id) REFERENCES reviewer_run(run_id,pr_id), UNIQUE(run_id,pr_id)
) STRICT;
CREATE TABLE adjudication(
  adjudication_id TEXT PRIMARY KEY, pr_id TEXT NOT NULL REFERENCES pull_request(pr_id),
  version INTEGER NOT NULL CHECK(version>0), supersedes_id TEXT,
  artifact_sha256 TEXT NOT NULL UNIQUE CHECK(length(artifact_sha256)=71), artifact_bytes BLOB NOT NULL,
  review_a_run_id TEXT NOT NULL, review_a_lane TEXT NOT NULL CHECK(review_a_lane='A'),
  review_b_run_id TEXT NOT NULL, review_b_lane TEXT NOT NULL CHECK(review_b_lane='B'),
  adjudicator_kind TEXT NOT NULL CHECK(adjudicator_kind IN ('human','agent')),
  adjudicator_name TEXT NOT NULL, adjudicator_version TEXT NOT NULL,
  prompt_sha256 TEXT NOT NULL CHECK(length(prompt_sha256)=71),
  terminal_status TEXT NOT NULL CHECK(terminal_status IN ('positive','negative_control','unknown','not_evaluable')),
  reason TEXT NOT NULL, import_batch_id TEXT NOT NULL REFERENCES import_batch(batch_id),
  FOREIGN KEY(supersedes_id,pr_id) REFERENCES adjudication(adjudication_id,pr_id),
  FOREIGN KEY(review_a_run_id,pr_id,review_a_lane) REFERENCES reviewer_run(run_id,pr_id,lane),
  FOREIGN KEY(review_b_run_id,pr_id,review_b_lane) REFERENCES reviewer_run(run_id,pr_id,lane),
  UNIQUE(pr_id,version), UNIQUE(adjudication_id,pr_id)
) STRICT;
CREATE TABLE adjudication_decision(
  decision_id TEXT PRIMARY KEY, adjudication_id TEXT NOT NULL, pr_id TEXT NOT NULL,
  local_decision_id TEXT NOT NULL,
  decision_kind TEXT NOT NULL CHECK(decision_kind IN ('entrypoint','terminal','unknown')),
  outcome TEXT NOT NULL CHECK(outcome IN ('include','exclude')),
  attribution TEXT NOT NULL CHECK(attribution IN ('A','B','both','newly_inspected')),
  rationale TEXT NOT NULL,
  FOREIGN KEY(adjudication_id,pr_id) REFERENCES adjudication(adjudication_id,pr_id),
  UNIQUE(adjudication_id,local_decision_id), UNIQUE(decision_id,pr_id), UNIQUE(decision_id,adjudication_id,pr_id)
) STRICT;
CREATE TABLE decision_source_claim(
  decision_id TEXT NOT NULL, adjudication_id TEXT NOT NULL, claim_id TEXT NOT NULL, pr_id TEXT NOT NULL,
  FOREIGN KEY(decision_id,adjudication_id,pr_id) REFERENCES adjudication_decision(decision_id,adjudication_id,pr_id),
  FOREIGN KEY(claim_id,pr_id) REFERENCES review_claim(claim_id,pr_id),
  PRIMARY KEY(decision_id,claim_id), UNIQUE(adjudication_id,claim_id)
) WITHOUT ROWID, STRICT;
CREATE TABLE decision_source_terminal(
  decision_id TEXT NOT NULL, adjudication_id TEXT NOT NULL, run_id TEXT NOT NULL, pr_id TEXT NOT NULL,
  FOREIGN KEY(decision_id,adjudication_id,pr_id) REFERENCES adjudication_decision(decision_id,adjudication_id,pr_id),
  FOREIGN KEY(run_id,pr_id) REFERENCES reviewer_run(run_id,pr_id),
  PRIMARY KEY(decision_id,run_id), UNIQUE(adjudication_id,run_id)
) WITHOUT ROWID, STRICT;
CREATE TABLE decision_source_unknown(
  decision_id TEXT NOT NULL, adjudication_id TEXT NOT NULL, unknown_id TEXT NOT NULL, pr_id TEXT NOT NULL,
  FOREIGN KEY(decision_id,adjudication_id,pr_id) REFERENCES adjudication_decision(decision_id,adjudication_id,pr_id),
  FOREIGN KEY(unknown_id,pr_id) REFERENCES review_unknown(unknown_id,pr_id),
  PRIMARY KEY(decision_id,unknown_id), UNIQUE(adjudication_id,unknown_id)
) WITHOUT ROWID, STRICT;
CREATE TABLE decision_source_negative(
  decision_id TEXT NOT NULL, adjudication_id TEXT NOT NULL, run_id TEXT NOT NULL, pr_id TEXT NOT NULL,
  FOREIGN KEY(decision_id,adjudication_id,pr_id) REFERENCES adjudication_decision(decision_id,adjudication_id,pr_id),
  FOREIGN KEY(run_id,pr_id) REFERENCES review_negative_assessment(run_id,pr_id),
  PRIMARY KEY(decision_id,run_id), UNIQUE(adjudication_id,run_id)
) WITHOUT ROWID, STRICT;
CREATE TABLE canonical_entrypoint(
  entrypoint_id TEXT PRIMARY KEY, decision_id TEXT NOT NULL, adjudication_id TEXT NOT NULL, pr_id TEXT NOT NULL,
  public_id TEXT NOT NULL, kind TEXT NOT NULL, confidence TEXT NOT NULL,
  FOREIGN KEY(decision_id,adjudication_id,pr_id) REFERENCES adjudication_decision(decision_id,adjudication_id,pr_id),
  UNIQUE(decision_id), UNIQUE(adjudication_id,public_id,kind)
) STRICT;
CREATE TABLE adjudication_evidence_edge(
  edge_id TEXT PRIMARY KEY, decision_id TEXT NOT NULL, pr_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL CHECK(ordinal>=0), relation TEXT NOT NULL,
  from_location_id TEXT NOT NULL, to_location_id TEXT NOT NULL,
  FOREIGN KEY(decision_id,pr_id) REFERENCES adjudication_decision(decision_id,pr_id),
  FOREIGN KEY(from_location_id,pr_id) REFERENCES evidence_location(location_id,pr_id),
  FOREIGN KEY(to_location_id,pr_id) REFERENCES evidence_location(location_id,pr_id),
  UNIQUE(decision_id,ordinal)
) STRICT;
CREATE TABLE adjudication_unknown(
  unknown_id TEXT PRIMARY KEY, adjudication_id TEXT NOT NULL, pr_id TEXT NOT NULL,
  local_unknown_id TEXT NOT NULL, category TEXT NOT NULL, description TEXT NOT NULL, evidence_limit TEXT NOT NULL,
  FOREIGN KEY(adjudication_id,pr_id) REFERENCES adjudication(adjudication_id,pr_id),
  UNIQUE(adjudication_id,local_unknown_id)
) STRICT;
CREATE TABLE adjudication_negative_assessment(
  adjudication_id TEXT PRIMARY KEY, pr_id TEXT NOT NULL,
  changed_symbol_census_complete INTEGER NOT NULL CHECK(changed_symbol_census_complete=1),
  searched_families_json TEXT NOT NULL CHECK(json_valid(searched_families_json)), limitations_json TEXT NOT NULL CHECK(json_valid(limitations_json)),
  FOREIGN KEY(adjudication_id,pr_id) REFERENCES adjudication(adjudication_id,pr_id)
) STRICT;
CREATE TABLE scope_definition(
  scope_id TEXT NOT NULL, scope_version INTEGER NOT NULL CHECK(scope_version>0),
  product TEXT NOT NULL, definition_sha256 TEXT NOT NULL CHECK(length(definition_sha256)=71),
  PRIMARY KEY(scope_id,scope_version)
) WITHOUT ROWID, STRICT;
CREATE TABLE scope_membership(
  membership_id TEXT PRIMARY KEY, adjudication_id TEXT NOT NULL, decision_id TEXT NOT NULL, pr_id TEXT NOT NULL,
  scope_id TEXT NOT NULL, scope_version INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('in_scope','out_of_scope')), rationale TEXT NOT NULL,
  FOREIGN KEY(decision_id,adjudication_id,pr_id) REFERENCES adjudication_decision(decision_id,adjudication_id,pr_id),
  FOREIGN KEY(scope_id,scope_version) REFERENCES scope_definition(scope_id,scope_version),
  UNIQUE(decision_id,scope_id,scope_version)
) STRICT;
CREATE TABLE publication_review(
  publication_review_id TEXT PRIMARY KEY, artifact_sha256 TEXT NOT NULL UNIQUE,
  artifact_bytes BLOB NOT NULL, release_id TEXT NOT NULL UNIQUE,
  reviewer_name TEXT NOT NULL, reviewed_at TEXT NOT NULL
) STRICT;
CREATE TABLE release(
  release_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL CHECK(schema_version=1),
  corpus_id TEXT NOT NULL REFERENCES corpus(corpus_id), corpus_sha256 TEXT NOT NULL,
  schema_sha256 TEXT NOT NULL, prompt_set_sha256 TEXT NOT NULL,
  publication_review_sha256 TEXT NOT NULL REFERENCES publication_review(artifact_sha256),
  created_at TEXT NOT NULL CHECK(created_at GLOB '*Z'), predecessor_release_id TEXT REFERENCES release(release_id),
  content_root TEXT NOT NULL UNIQUE CHECK(length(content_root)=71), manifest_bytes BLOB NOT NULL,
  UNIQUE(release_id,corpus_id)
) STRICT;
CREATE TABLE release_pr(
  release_id TEXT NOT NULL, corpus_id TEXT NOT NULL, pr_id TEXT NOT NULL, adjudication_id TEXT NOT NULL,
  FOREIGN KEY(release_id,corpus_id) REFERENCES release(release_id,corpus_id),
  FOREIGN KEY(pr_id,corpus_id) REFERENCES pull_request(pr_id,corpus_id),
  FOREIGN KEY(adjudication_id,pr_id) REFERENCES adjudication(adjudication_id,pr_id),
  PRIMARY KEY(release_id,pr_id), UNIQUE(release_id,adjudication_id)
) WITHOUT ROWID, STRICT;

CREATE TRIGGER adjudication_same_pr_insert BEFORE INSERT ON adjudication
WHEN NEW.supersedes_id IS NOT NULL AND NOT EXISTS(
 SELECT 1 FROM adjudication old WHERE old.adjudication_id=NEW.supersedes_id AND old.pr_id=NEW.pr_id AND old.version<NEW.version
) BEGIN SELECT RAISE(ABORT,'invalid adjudication predecessor'); END;
CREATE TRIGGER scope_membership_entrypoint_insert BEFORE INSERT ON scope_membership
WHEN NOT EXISTS(
 SELECT 1 FROM adjudication_decision d WHERE d.decision_id=NEW.decision_id
 AND d.adjudication_id=NEW.adjudication_id AND d.pr_id=NEW.pr_id
 AND d.decision_kind='entrypoint' AND d.outcome='include'
) BEGIN SELECT RAISE(ABORT,'scope membership requires an included entrypoint decision'); END;

-- All canonical content is append-only. Corrections append adjudications/releases.
CREATE TRIGGER corpus_no_update BEFORE UPDATE ON corpus BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER corpus_no_delete BEFORE DELETE ON corpus BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER schema_migration_no_update BEFORE UPDATE ON schema_migration BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER schema_migration_no_delete BEFORE DELETE ON schema_migration BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER repository_no_update BEFORE UPDATE ON repository BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER repository_no_delete BEFORE DELETE ON repository BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER pull_request_no_update BEFORE UPDATE ON pull_request BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER pull_request_no_delete BEFORE DELETE ON pull_request BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER snapshot_no_update BEFORE UPDATE ON snapshot BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER snapshot_no_delete BEFORE DELETE ON snapshot BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER remote_diff_no_update BEFORE UPDATE ON remote_diff BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER remote_diff_no_delete BEFORE DELETE ON remote_diff BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER import_batch_no_update BEFORE UPDATE ON import_batch BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER import_batch_no_delete BEFORE DELETE ON import_batch BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER evidence_location_no_update BEFORE UPDATE ON evidence_location BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER evidence_location_no_delete BEFORE DELETE ON evidence_location BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER reviewer_run_no_update BEFORE UPDATE ON reviewer_run BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER reviewer_run_no_delete BEFORE DELETE ON reviewer_run BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER review_changed_symbol_no_update BEFORE UPDATE ON review_changed_symbol BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER review_changed_symbol_no_delete BEFORE DELETE ON review_changed_symbol BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER review_claim_no_update BEFORE UPDATE ON review_claim BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER review_claim_no_delete BEFORE DELETE ON review_claim BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER review_entrypoint_no_update BEFORE UPDATE ON review_entrypoint BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER review_entrypoint_no_delete BEFORE DELETE ON review_entrypoint BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER review_evidence_edge_no_update BEFORE UPDATE ON review_evidence_edge BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER review_evidence_edge_no_delete BEFORE DELETE ON review_evidence_edge BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER review_unknown_no_update BEFORE UPDATE ON review_unknown BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER review_unknown_no_delete BEFORE DELETE ON review_unknown BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER review_negative_assessment_no_update BEFORE UPDATE ON review_negative_assessment BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER review_negative_assessment_no_delete BEFORE DELETE ON review_negative_assessment BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER adjudication_no_update BEFORE UPDATE ON adjudication BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER adjudication_no_delete BEFORE DELETE ON adjudication BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER adjudication_decision_no_update BEFORE UPDATE ON adjudication_decision BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER adjudication_decision_no_delete BEFORE DELETE ON adjudication_decision BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER decision_source_claim_no_update BEFORE UPDATE ON decision_source_claim BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER decision_source_claim_no_delete BEFORE DELETE ON decision_source_claim BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER decision_source_terminal_no_update BEFORE UPDATE ON decision_source_terminal BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER decision_source_terminal_no_delete BEFORE DELETE ON decision_source_terminal BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER decision_source_unknown_no_update BEFORE UPDATE ON decision_source_unknown BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER decision_source_unknown_no_delete BEFORE DELETE ON decision_source_unknown BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER decision_source_negative_no_update BEFORE UPDATE ON decision_source_negative BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER decision_source_negative_no_delete BEFORE DELETE ON decision_source_negative BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER canonical_entrypoint_no_update BEFORE UPDATE ON canonical_entrypoint BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER canonical_entrypoint_no_delete BEFORE DELETE ON canonical_entrypoint BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER adjudication_evidence_edge_no_update BEFORE UPDATE ON adjudication_evidence_edge BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER adjudication_evidence_edge_no_delete BEFORE DELETE ON adjudication_evidence_edge BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER adjudication_unknown_no_update BEFORE UPDATE ON adjudication_unknown BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER adjudication_unknown_no_delete BEFORE DELETE ON adjudication_unknown BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER adjudication_negative_assessment_no_update BEFORE UPDATE ON adjudication_negative_assessment BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER adjudication_negative_assessment_no_delete BEFORE DELETE ON adjudication_negative_assessment BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER scope_definition_no_update BEFORE UPDATE ON scope_definition BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER scope_definition_no_delete BEFORE DELETE ON scope_definition BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER scope_membership_no_update BEFORE UPDATE ON scope_membership BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER scope_membership_no_delete BEFORE DELETE ON scope_membership BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER publication_review_no_update BEFORE UPDATE ON publication_review BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER publication_review_no_delete BEFORE DELETE ON publication_review BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER release_no_update BEFORE UPDATE ON release BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER release_no_delete BEFORE DELETE ON release BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER release_pr_no_update BEFORE UPDATE ON release_pr BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER release_pr_no_delete BEFORE DELETE ON release_pr BEGIN SELECT RAISE(ABORT,'append-only'); END;
