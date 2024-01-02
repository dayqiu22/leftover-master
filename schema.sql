CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  google_id TEXT UNIQUE,
  username TEXT NOT NULL,
  hash TEXT,
  email TEXT,
  user_type TEXT NOT NULL
);
CREATE TABLE foods (
  id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 
  user_id INTERGER NOT NULL, 
  name TEXT NOT NULL, 
  food_group TEXT NOT NULL, 
  location TEXT NOT NULL, 
  start_date TEXT NOT NULL, 
  best_before TEXT NOT NULL, 
  portions INTEGER NOT NULL
);