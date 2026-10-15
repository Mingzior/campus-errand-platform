-- Campus Errand: initial Supabase schema (review before production)
-- Run in Supabase SQL Editor using a project you control.
-- This is a starting point, not a complete production security review.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null check (char_length(display_name) between 1 and 40),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.tasks (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete restrict,
  runner_id uuid references auth.users(id) on delete set null,
  applicant_id uuid references auth.users(id) on delete set null,
  title text not null check (char_length(title) between 4 and 40),
  category text not null check (category in ('快递代取','顺路带物','学习用品','其他互助')),
  description text not null check (char_length(description) between 8 and 400),
  area text not null check (char_length(area) between 1 and 40),
  deadline timestamptz not null,
  estimated_minutes integer not null check (estimated_minutes between 5 and 240),
  reward numeric(7,2) not null check (reward between 0 and 200),
  status text not null default '待承接'
    check (status in ('待承接','待确认','进行中','待完成确认','已完成','已取消','争议中')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (deadline > created_at),
  check (owner_id <> runner_id or runner_id is null)
);

create index if not exists tasks_status_deadline_idx on public.tasks(status, deadline);
create index if not exists tasks_owner_created_idx on public.tasks(owner_id, created_at desc);
create index if not exists tasks_runner_created_idx on public.tasks(runner_id, created_at desc);

create table if not exists public.task_events (
  id uuid primary key default gen_random_uuid(),
  task_id uuid not null references public.tasks(id) on delete cascade,
  actor_id uuid references auth.users(id) on delete set null,
  action text not null check (char_length(action) between 1 and 80),
  note text not null default '' check (char_length(note) <= 500),
  created_at timestamptz not null default now()
);
create index if not exists task_events_task_created_idx on public.task_events(task_id, created_at desc);

create table if not exists public.reports (
  id uuid primary key default gen_random_uuid(),
  task_id uuid references public.tasks(id) on delete set null,
  reporter_id uuid not null references auth.users(id) on delete restrict,
  reason_code text not null check (reason_code in ('违规任务','隐私信息','可疑要求','履约争议','其他')),
  description text not null check (char_length(description) between 5 and 1000),
  status text not null default '待处理'
    check (status in ('待处理','处理中','已处理','不成立','需升级')),
  resolution_note text check (resolution_note is null or char_length(resolution_note) <= 1000),
  reviewer_id uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists reports_status_created_idx on public.reports(status, created_at desc);

-- Enable Row Level Security on every table.
alter table public.profiles enable row level security;
alter table public.tasks enable row level security;
alter table public.task_events enable row level security;
alter table public.reports enable row level security;

-- Profiles: authenticated users may read basic display names and update only their own row.
create policy "profiles_select_authenticated"
on public.profiles for select to authenticated
using (true);

create policy "profiles_insert_own"
on public.profiles for insert to authenticated
with check (auth.uid() = id);

create policy "profiles_update_own"
on public.profiles for update to authenticated
using (auth.uid() = id)
with check (auth.uid() = id);

-- Tasks: signed-in users can read open task cards; participants can read their own task.
-- Do not add private contact fields to this table.
create policy "tasks_select_open_or_participant"
on public.tasks for select to authenticated
using (
  (status = '待承接' and deadline > now())
  or owner_id = auth.uid()
  or runner_id = auth.uid()
  or applicant_id = auth.uid()
);

create policy "tasks_insert_own"
on public.tasks for insert to authenticated
with check (
  owner_id = auth.uid()
  and runner_id is null
  and applicant_id is null
  and status = '待承接'
);

-- No direct client UPDATE policy is granted intentionally. Add carefully reviewed
-- transactional RPC functions for each permitted state transition before enabling
-- updates; this prevents clients from changing runner_id/status arbitrarily.

-- Events can be read only by task participants. Inserts are restricted to the actor,
-- but production should write events from trusted transactional functions to prevent spoofed history.
create policy "events_select_participants"
on public.task_events for select to authenticated
using (exists (
  select 1 from public.tasks t
  where t.id = task_id
    and (t.owner_id = auth.uid() or t.runner_id = auth.uid() or t.applicant_id = auth.uid())
));

-- No direct client INSERT policy is granted for events. Trusted transactional RPC
-- functions should append events atomically with each accepted state transition.

-- Reports: reporter can create and read their own reports. No client-side policy grants
-- general read access or review updates. Add reviewer access only after defining a
-- trusted reviewer role and an audited review workflow.
create policy "reports_insert_own"
on public.reports for insert to authenticated
with check (reporter_id = auth.uid() and status = '待处理' and reviewer_id is null);

create policy "reports_select_own"
on public.reports for select to authenticated
using (reporter_id = auth.uid());

-- IMPORTANT PRODUCTION TODO:
-- 1. Add transactional SECURITY DEFINER RPC functions with fixed search_path for
--    apply_task, accept_applicant, cancel_task, submit_completion, confirm_completion,
--    open_dispute and append_task_event.
-- 3. Enforce valid state transitions and single-runner acceptance atomically.
-- 4. Define a trusted reviewer role and tightly scoped report review access.
-- 5. Review profile visibility, anti-abuse/rate limiting, deletion/retention, backups,
--    and applicable school/privacy requirements before real pilot use.
