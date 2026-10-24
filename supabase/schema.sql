-- Socially starter schema for Supabase/Postgres.
-- Apply only after creating a Supabase project and reviewing the policies below.
-- AI-generated writes should be performed by trusted server-side functions using the service role;
-- never ship the service-role key or model API keys to the browser.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  handle text unique not null check (handle ~ '^[A-Za-z0-9_.]{3,30}$'),
  display_name text not null default 'Socially user',
  bio text not null default '',
  avatar_url text,
  created_at timestamptz not null default now()
);

create table if not exists public.ai_personas (
  id uuid primary key default gen_random_uuid(),
  handle text unique not null,
  display_name text not null,
  bio text not null default '',
  avatar_url text,
  role text not null default '',
  interests text[] not null default '{}',
  personality jsonb not null default '{}'::jsonb,
  memory_summary text not null default '',
  is_active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.follows (
  follower_id uuid not null references public.profiles(id) on delete cascade,
  followed_user_id uuid references public.profiles(id) on delete cascade,
  followed_persona_id uuid references public.ai_personas(id) on delete cascade,
  created_at timestamptz not null default now(),
  check (num_nonnulls(followed_user_id, followed_persona_id) = 1),
  check (followed_user_id is null or follower_id <> followed_user_id)
);
create unique index if not exists follows_user_unique on public.follows(follower_id, followed_user_id) where followed_user_id is not null;
create unique index if not exists follows_persona_unique on public.follows(follower_id, followed_persona_id) where followed_persona_id is not null;

create table if not exists public.posts (
  id uuid primary key default gen_random_uuid(),
  author_user_id uuid references public.profiles(id) on delete cascade,
  author_persona_id uuid references public.ai_personas(id) on delete cascade,
  caption text not null default '',
  image_url text,
  location text,
  is_ai_generated boolean not null default false,
  created_at timestamptz not null default now(),
  check (num_nonnulls(author_user_id, author_persona_id) = 1),
  check ((author_persona_id is not null) = is_ai_generated)
);
create index if not exists posts_created_at_idx on public.posts(created_at desc);

create table if not exists public.stories (
  id uuid primary key default gen_random_uuid(),
  author_user_id uuid references public.profiles(id) on delete cascade,
  author_persona_id uuid references public.ai_personas(id) on delete cascade,
  media_url text not null,
  caption text not null default '',
  is_ai_generated boolean not null default false,
  expires_at timestamptz not null default (now() + interval '24 hours'),
  created_at timestamptz not null default now(),
  check (num_nonnulls(author_user_id, author_persona_id) = 1),
  check ((author_persona_id is not null) = is_ai_generated)
);
create index if not exists stories_expires_at_idx on public.stories(expires_at);

create table if not exists public.comments (
  id uuid primary key default gen_random_uuid(),
  post_id uuid not null references public.posts(id) on delete cascade,
  author_user_id uuid references public.profiles(id) on delete cascade,
  author_persona_id uuid references public.ai_personas(id) on delete cascade,
  body text not null check (char_length(body) between 1 and 2200),
  is_ai_generated boolean not null default false,
  created_at timestamptz not null default now(),
  check (num_nonnulls(author_user_id, author_persona_id) = 1),
  check ((author_persona_id is not null) = is_ai_generated)
);
create index if not exists comments_post_created_idx on public.comments(post_id, created_at);

create table if not exists public.post_likes (
  post_id uuid not null references public.posts(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (post_id, user_id)
);

create table if not exists public.saved_posts (
  post_id uuid not null references public.posts(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (post_id, user_id)
);

create table if not exists public.conversations (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table if not exists public.conversation_members (
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  user_id uuid references public.profiles(id) on delete cascade,
  persona_id uuid references public.ai_personas(id) on delete cascade,
  joined_at timestamptz not null default now(),
  check (num_nonnulls(user_id, persona_id) = 1)
);
create unique index if not exists conversation_member_user_unique on public.conversation_members(conversation_id, user_id) where user_id is not null;
create unique index if not exists conversation_member_persona_unique on public.conversation_members(conversation_id, persona_id) where persona_id is not null;

create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  sender_user_id uuid references public.profiles(id) on delete cascade,
  sender_persona_id uuid references public.ai_personas(id) on delete cascade,
  body text not null check (char_length(body) between 1 and 5000),
  is_ai_generated boolean not null default false,
  created_at timestamptz not null default now(),
  check (num_nonnulls(sender_user_id, sender_persona_id) = 1),
  check ((sender_persona_id is not null) = is_ai_generated)
);
create index if not exists messages_conversation_created_idx on public.messages(conversation_id, created_at);

create table if not exists public.persona_memories (
  id uuid primary key default gen_random_uuid(),
  persona_id uuid not null references public.ai_personas(id) on delete cascade,
  about_user_id uuid references public.profiles(id) on delete cascade,
  memory text not null,
  source_type text not null default 'conversation',
  created_at timestamptz not null default now()
);
create index if not exists persona_memories_lookup_idx on public.persona_memories(persona_id, about_user_id, created_at desc);

alter table public.profiles enable row level security;
alter table public.ai_personas enable row level security;
alter table public.follows enable row level security;
alter table public.posts enable row level security;
alter table public.stories enable row level security;
alter table public.comments enable row level security;
alter table public.post_likes enable row level security;
alter table public.saved_posts enable row level security;
alter table public.conversations enable row level security;
alter table public.conversation_members enable row level security;
alter table public.messages enable row level security;
alter table public.persona_memories enable row level security;

-- SECURITY DEFINER avoids recursive RLS evaluation when checking conversation membership.
create or replace function public.is_conversation_member(p_conversation_id uuid, p_user_id uuid default auth.uid())
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $
  select exists (
    select 1 from public.conversation_members cm
    where cm.conversation_id = p_conversation_id and cm.user_id = p_user_id
  );
$;
revoke all on function public.is_conversation_member(uuid, uuid) from public;
grant execute on function public.is_conversation_member(uuid, uuid) to authenticated;

-- Public, read-only social surfaces for signed-in users.
create policy "profiles are readable" on public.profiles for select to authenticated using (true);
create policy "users create own profile" on public.profiles for insert to authenticated with check (id = auth.uid());
create policy "users update own profile" on public.profiles for update to authenticated using (id = auth.uid()) with check (id = auth.uid());

create policy "active personas are readable" on public.ai_personas for select to authenticated using (is_active);
create policy "follows are readable" on public.follows for select to authenticated using (true);
create policy "users follow as self" on public.follows for insert to authenticated with check (follower_id = auth.uid());
create policy "users unfollow as self" on public.follows for delete to authenticated using (follower_id = auth.uid());

create policy "posts are readable" on public.posts for select to authenticated using (true);
create policy "users create own posts" on public.posts for insert to authenticated with check (author_user_id = auth.uid() and author_persona_id is null and is_ai_generated = false);
create policy "users edit own posts" on public.posts for update to authenticated using (author_user_id = auth.uid() and author_persona_id is null) with check (author_user_id = auth.uid() and author_persona_id is null);
create policy "users delete own posts" on public.posts for delete to authenticated using (author_user_id = auth.uid() and author_persona_id is null);

create policy "unexpired stories are readable" on public.stories for select to authenticated using (expires_at > now());
create policy "users create own stories" on public.stories for insert to authenticated with check (author_user_id = auth.uid() and author_persona_id is null and is_ai_generated = false);
create policy "comments are readable" on public.comments for select to authenticated using (true);
create policy "users write own comments" on public.comments for insert to authenticated with check (author_user_id = auth.uid() and author_persona_id is null and is_ai_generated = false);
create policy "users delete own comments" on public.comments for delete to authenticated using (author_user_id = auth.uid() and author_persona_id is null);

create policy "likes are readable" on public.post_likes for select to authenticated using (true);
create policy "users like as self" on public.post_likes for insert to authenticated with check (user_id = auth.uid());
create policy "users unlike as self" on public.post_likes for delete to authenticated using (user_id = auth.uid());
create policy "users read own saves" on public.saved_posts for select to authenticated using (user_id = auth.uid());
create policy "users save as self" on public.saved_posts for insert to authenticated with check (user_id = auth.uid());
create policy "users unsave as self" on public.saved_posts for delete to authenticated using (user_id = auth.uid());

-- Conversation/message policies rely on a SECURITY DEFINER membership helper.
-- AI responses are written server-side.
create policy "members read conversations" on public.conversations for select to authenticated using (
  public.is_conversation_member(conversations.id, auth.uid())
);
create policy "members read memberships" on public.conversation_members for select to authenticated using (
  public.is_conversation_member(conversation_members.conversation_id, auth.uid())
);
create policy "users join conversation as self" on public.conversation_members for insert to authenticated with check (user_id = auth.uid() and persona_id is null);
create policy "members read messages" on public.messages for select to authenticated using (
  public.is_conversation_member(messages.conversation_id, auth.uid())
);
create policy "users send own messages" on public.messages for insert to authenticated with check (
  sender_user_id = auth.uid() and sender_persona_id is null and is_ai_generated = false and
  public.is_conversation_member(messages.conversation_id, auth.uid())
);
create policy "users read own persona memories" on public.persona_memories for select to authenticated using (about_user_id = auth.uid());

-- Do not grant client write policies on AI personas, AI-generated posts/comments/stories/messages,
-- or persona memories. Use trusted server-side code/service-role access for those operations.
