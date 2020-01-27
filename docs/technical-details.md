# Technical Details <!-- omit in toc -->
This section talks about the technical details of the extension.

- [Optimizations](#optimizations)
    - [JavaScript Detection](#javascript-detection)
    - [Duplicate Asset Detection](#duplicate-asset-detection)
    - [Using Threadpools](#using-threadpools)
    - [SQLite Database to Persists Data](#sqlite-database-to-persists-data)
- [Request/Response Processing Logic](#requestresponse-processing-logic)

## Optimizations

### JavaScript Detection
The extension uses some simple ways to detect JavaScript in responses. Most of
it is guided by the items in the config file (see "Configuring JavaScript
Detection" in [configuration.md](configuration.md)).

* MIME type returned by Burp.
* `Content-Type` response header.
* URL extension. E.g., everything that ends in `.js`.

### Duplicate Asset Detection
The extension generates the hash of all JavaScript in a response and uses it to
detect duplicates. If a certain JavaScript file (or content) is processed before
and exists in the database, it's not processed again its record is updated when
it's entered into the database. This is done with the trigger
`resources/db/update_hash-trigger.sql`.

### Using Threadpools
Each request, response and compute task is added to a threadpool. But
configuring the number of threads, we can optimize the extension for the machine
and load. Data are queued and submitted to the threadpool and are not lost.

### SQLite Database to Persists Data
Each request and response is stored in a SQLite database. Closing the extension
before some are processed does not lose the data. When the extension is loaded
again and the `Process` button is toggled, all rows will be read from the
database and processed again.

Every beautified JavaScript and its ESLint results are also stored on the file
system.

## Request/Response Processing Logic

1. Check if we got a request.
2. If it's a request, remove the headers and return.
3. If it's a response, check for JavaScript.
4. Extract the JavaScript.
5. Check the database to see if hash of body is already in the table.
6. If hash exists.
    1. Copy `beautified_javascript`, `status`, `results`, `is_processed` and
       `number_of_results`.
    2. If `is_processed == 0`, then the rest of the columns do not have valid
       data and will be populated when this hash is processed.
    3. Store the beautified JS file and results in their correct places.
    4. Go to 8.
7. If hash does not exist.
    1. Beautify the extracted JS.
    2. Populate the rest of the columns.
        1. `beautified_javascript`: Beautified extracted JS.
        2. `status` = pending.
        3. `results` = empty. Don't care.
        4. `is_processed` = 0.
        5. `number_of_results` = 0. Don't care.
    3. Store the beautified JS file and results in their correct places.
    4. Go to 8.
8. Add the request to the table.