UPDATE eslint
SET
    beautified_javascript = ?,
    status = ?,
    results = ?,
    is_processed = ?,
    number_of_results = ?
WHERE
    metadata = ?