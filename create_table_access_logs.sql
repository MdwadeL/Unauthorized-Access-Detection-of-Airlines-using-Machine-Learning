create type user_role as enum('HR', 'Finance', 'IT', 'Customer Service', 'Pilot');
create type access_type as enum('write', 'read', 'export', 'delete');


create table access_logs(
  event_id bigint primary key,
  user_id int not null,
  user_role user_role not null,
  resource_accessed varchar(50) not null,
  resource_sens boolean not null,
  access_timestamp timestamp not null,
  location varchar(50) not null,
  device_type varchar(50) not null,
  access_type access_type not null,
  records_viewed int not null,
  is_authorized boolean not null,
  is_privacy_violation boolean not null
);











