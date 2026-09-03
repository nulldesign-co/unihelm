-- Which language an application runs.
--
-- Every row that exists is a Node app, because Node was the only thing this
-- panel could run — so the default is not a guess, it is what those rows are.
-- NOT NULL with that default, rather than nullable: an application without a
-- runtime is not a state worth being able to represent.
ALTER TABLE node_apps ADD COLUMN runtime TEXT NOT NULL DEFAULT 'node';
