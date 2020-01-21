CREATE TABLE IF NOT EXISTS eslint (
    metadata TEXT NOT NULL,
    url TEXT,
    hash TEXT,
    beautified_javascript TEXT,
    status TEXT,
    results TEXT,
    is_processed INTEGER,
    number_of_results INTEGER,
    PRIMARY KEY (metadata)
) WITHOUT ROWID;
