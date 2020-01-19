CREATE TRIGGER IF NOT EXISTS check_if_already_processed_after_insert
AFTER INSERT ON eslint
WHEN
    new.is_processed == 0 AND
    EXISTS (SELECT 1 FROM eslint WHERE is_processed == 1 AND hash = new.hash)
BEGIN
    /* We want to check if the hash is already in the table. If new.hash is
        already in the table with is_processed = 1 then we want to update the
        status, eslint, is_processed and number_of_results from the first existing row.
        This might be problematic later but in theory (at least) all the tables
        with is_processed=1 and the same hash should have the same results. */

    UPDATE eslint
    SET
        (beautified_javascript, status, is_processed, results, number_of_results) =
            (
                SELECT e.beautified_javascript, e.status, e.is_processed, e.results, e.number_of_results
                FROM eslint e
                WHERE
                    new.hash = e.hash AND e.is_processed == 1
            )
    WHERE
        /* This should only target the last inserted row. */
        url == new.url AND referer == new.referer AND hash == new.hash;
END;
