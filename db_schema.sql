create table if not exists users (
	user_id	integer not null unique primary key autoincrement,
	uuid blob not null unique
)
