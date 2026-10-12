-- AI Security Platform: database schema for Supabase (Postgres)
-- Run this once: Supabase dashboard -> SQL Editor -> New query -> paste -> Run.

create table if not exists request_logs (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  client text,
  source text,                       -- api | demo | scanner | openai-compat
  protected boolean,
  action text,                       -- allowed | blocked
  risk_score int,
  matched_rules jsonb not null default '[]',
  pii_findings jsonb not null default '{}',
  prompt_redacted text,              -- prompts are stored with sensitive data already hidden
  response_redacted text,
  latency_ms int
);

create table if not exists scan_runs (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  protected boolean,
  total int,
  leaked int,
  score int,
  summary jsonb
);

create table if not exists scan_results (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  run_id uuid references scan_runs(id) on delete cascade,
  attack_id text,
  category text,
  name text,
  prompt text,
  verdict text,                      -- blocked | contained | resisted | leaked | error
  response_excerpt text,
  risk_score int
);

create table if not exists agent_policies (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  agent_id text not null,
  tool text not null,                -- a tool name, or * for "any other tool"
  decision text not null check (decision in ('allow', 'deny', 'require_approval')),
  unique (agent_id, tool)
);

create table if not exists tool_calls (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  agent_id text,
  tool text,
  arguments jsonb not null default '{}',
  decision text,
  status text,                       -- allowed | denied | pending | approved | rejected
  reason text
);

create index if not exists request_logs_created_idx on request_logs (created_at desc);
create index if not exists scan_results_run_idx on scan_results (run_id);
create index if not exists tool_calls_created_idx on tool_calls (created_at desc);

-- Security: turn on Row Level Security and add NO policies.
-- That means the public "anon" key can read and write nothing.
-- Only the backend, using the secret service_role key, can touch these tables.
alter table request_logs enable row level security;
alter table scan_runs enable row level security;
alter table scan_results enable row level security;
alter table agent_policies enable row level security;
alter table tool_calls enable row level security;
