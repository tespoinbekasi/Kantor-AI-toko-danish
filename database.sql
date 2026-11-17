-- JALANKAN SEKALI di Supabase SQL Editor.
-- Semua akun baru berstatus tidak aktif. Owner pertama ditetapkan manual.
create extension if not exists pgcrypto;
create table if not exists public.profiles (
 user_id uuid primary key references auth.users(id) on delete cascade,
 email text not null,
 role text not null default 'admin' check (role in ('owner','admin')),
 active boolean not null default false,
 created_at timestamptz not null default now()
);
create table if not exists public.tasks (
 id uuid primary key default gen_random_uuid(),
 created_by uuid not null references auth.users(id),
 division text not null,
 title text not null,
 body text not null,
 status text not null default 'pending' check(status in ('pending','approved','rejected')),
 created_at timestamptz not null default now()
);
create table if not exists public.customers (
 id uuid primary key default gen_random_uuid(),
 created_by uuid not null references auth.users(id),
 name text not null,
 phone text not null default '',
 note text not null default '',
 created_at timestamptz not null default now()
);
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
 insert into public.profiles(user_id,email,role,active)
 values(new.id,coalesce(new.email,''),'admin',false)
 on conflict(user_id) do nothing;
 return new;
end; $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute function public.handle_new_user();
-- Backfill existing users safely (no privilege escalation).
insert into public.profiles(user_id,email,role,active)
select id,coalesce(email,''),'admin',false from auth.users
on conflict(user_id) do nothing;
create or replace function public.is_active_member()
returns boolean language sql stable security definer set search_path = ''
as $$ select exists(select 1 from public.profiles where user_id=(select auth.uid()) and active=true); $$;
create or replace function public.is_owner()
returns boolean language sql stable security definer set search_path = ''
as $$ select exists(select 1 from public.profiles where user_id=(select auth.uid()) and active=true and role='owner'); $$;
alter table public.profiles enable row level security;
alter table public.tasks enable row level security;
alter table public.customers enable row level security;
drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles for select to authenticated
using (user_id=(select auth.uid()) or public.is_owner());
drop policy if exists tasks_read on public.tasks;
create policy tasks_read on public.tasks for select to authenticated using(public.is_active_member());
drop policy if exists tasks_insert on public.tasks;
create policy tasks_insert on public.tasks for insert to authenticated
with check(public.is_active_member() and created_by=(select auth.uid()) and status='pending');
drop policy if exists tasks_update on public.tasks;
create policy tasks_update on public.tasks for update to authenticated
using(public.is_owner()) with check(public.is_owner());
drop policy if exists customers_read on public.customers;
create policy customers_read on public.customers for select to authenticated using(public.is_active_member());
drop policy if exists customers_insert on public.customers;
create policy customers_insert on public.customers for insert to authenticated
with check(public.is_active_member() and created_by=(select auth.uid()));
create or replace function public.activate_admin_by_email(target_email text)
returns void language plpgsql security definer set search_path = ''
as $$
begin
 if not public.is_owner() then raise exception 'Owner only'; end if;
 update public.profiles set active=true,role='admin'
 where lower(email)=lower(trim(target_email)) and role<>'owner';
 if not found then raise exception 'Akun admin tidak ditemukan atau tidak dapat diubah'; end if;
end; $$;
revoke all on function public.activate_admin_by_email(text) from public;
grant execute on function public.activate_admin_by_email(text) to authenticated;
grant usage on schema public to authenticated;
grant select on public.profiles to authenticated;
grant select,insert,update on public.tasks to authenticated;
grant select,insert on public.customers to authenticated;
-- PENTING: setelah akun Owner mendaftar, jalankan secara MANUAL,
-- ganti email dengan email Owner asli:
-- update public.profiles set role='owner', active=true
-- where lower(email)=lower('EMAIL_OWNER_ANDA@example.com');
-- Hanya jalankan perintah Owner di SQL Editor (jangan di browser).
