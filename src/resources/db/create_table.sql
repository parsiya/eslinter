CREATE TABLE IF NOT EXISTS eslint (
    url TEXT NOT NULL, 
    referer TEXT NOT NULL, 
    hash TEXT NOT NULL, 
    beautified_javascript TEXT,
    status TEXT, 
    results TEXT, 
    is_processed INTEGER, 
    number_of_results INTEGER, 
    PRIMARY KEY (url, referer, hash) 
) WITHOUT ROWID;