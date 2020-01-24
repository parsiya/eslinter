SELECT rowid, * FROM eslint
WHERE
    rowid > (?) AND is_processed != 1
ORDER BY
    rowid