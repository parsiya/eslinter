/*
    Every time a new row is updated with results, it also updates all the rows
    that have the same hash and their processed column is 0.
*/

CREATE TRIGGER IF NOT EXISTS update_for_all_hashes
AFTER UPDATE OF is_processed ON eslint
WHEN
    -- Only execute if we are updating the results.
    new.is_processed == 1
BEGIN
    UPDATE eslint
    SET
        -- beautified_javascript = new.beautified_javascript,
        status = new.status,
        results = new.results,
        is_processed = new.is_processed,
        number_of_results = new.number_of_results
    WHERE
        hash == new.hash AND is_processed == 0;
END;
