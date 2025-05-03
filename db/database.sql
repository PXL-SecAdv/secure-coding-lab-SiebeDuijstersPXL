create database pxldb;
\c pxldb

create user secadv with password '$2a$10$UujmAky37hGAZafffnYvVearyTFeknQ7lovq5Efngtq4CR8nM9PQm'; --hashed password
grant all privileges on database pxldb to secadv;
BEGIN;

create table users (id serial primary key, user_name text not null unique, password text not null);
grant all privileges on table users to secadv;

insert into users (user_name, password) values ('pxl-admin', '$2a$10$E99gCGfewt0UIPsmrMZHSOhtt5aGoBYF/dwcpD1MwJARcIK3b3L4q') ; --hashed password
insert into users (user_name, password) values ('george', '$2a$10$.XOGlaaMegXZLex1xBC1r.bS2VdJK06tFDxsXm/R/PaPzddt28Eme') ; --hashed password

COMMIT;