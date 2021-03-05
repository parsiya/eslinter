# Configuration <!-- omit in toc -->
`ESLinter` uses a config file in json format.

- [Loading and Storing Configurations](#loading-and-storing-configurations)
  - [The Default Configuration File](#the-default-configuration-file)
  - [Saving and Loading Configuration Files](#saving-and-loading-configuration-files)
- [Manual Configuration Steps](#manual-configuration-steps)
- [Configuration File Elements](#configuration-file-elements)
  - [Storage Paths](#storage-paths)
  - [Command Paths](#command-paths)
  - [Highlight Requests](#highlight-requests)
  - [Process Requests Created by Specific Burp Tools](#process-requests-created-by-specific-burp-tools)
  - [Only Process Requests in Scope](#only-process-requests-in-scope)
  - [Performance](#performance)
  - [Configuring JavaScript Detection](#configuring-javascript-detection)
    - [Pure JavaScript](#pure-javascript)
    - [Embedded JavaScript](#embedded-javascript)
  - [Removing Request Headers](#removing-request-headers)
  - [The Debug Flag](#the-debug-flag)

## Loading and Storing Configurations

### The Default Configuration File
At startup, the extension looks for a file named `config.json` in the same
path as the jar file. That file will override the current configuration. If
that file is modified, you need to reload the extension for the changes to take
effect.

For testing different configurations, create such a file and store it beside
the jar file. This will ensure that you are always using a configuration that
you have set.

### Saving and Loading Configuration Files
To create a prepopulated config file, use the `gradlew config` task.

To load a config file, use the `Load Config` button. `Save Config` saves the
current configuration to a file.

The extension saves the configuration to Burp's extension settings. There is no
need to load the configuration file every time the extension starts. After a
config is loaded, it will be reused (absent the existence of `config.json`
explained above).

## Manual Configuration Steps
It's recommended to use the `config` Gradle task. But you can also create your
own config files.

1. Create a sample config file. This could be an existing one or a new one
   created by the config.
2. Edit the config file in your favorite editor.
3. At a minimum, you need to provide paths to (see
   [docs/configuration.md](docs/configuration.md) for more information):
    * `beautified-javascript-path`: Path to store extracted JavaScript files.
    * `lint-result-path`: Path to store ESLint results.
    * `database-path`: Location of the target database (it will be created if it
      does not exist).
    * `rules-path`: Path to the ESLint configuration file.
    * `linter-command`: Path to the `eslint` command.
    * `jsbeautifier-command`:  Path to the `js-beautify` command.
4. Modify any other settings. See the
   [Configuration File Elements](#configuration-file-elements) section.
5. Put the config file in the `release` directory or where the jar
   file is located.

Note that Windows accepts paths with forward slashes. So
`c:/eslint-security/node_modules/.bin/eslint.cmd` is a valid path. If you are
providing paths with backslashes be sure to escape them. E.g.,
`c:\\eslint-security\\nod_modules\\.bin\\eslint.cmd`.

## Configuration File Elements
The configuration file provides several options to control the behavior of the
extension.

### Storage Paths
The extension stores every extracted JavaScript and every ESLint result on
the file system, too. This can be used to quickly see every result without
having to export it from the database.

* `beautified-javascript-path`: Where all beautified JavaScripts are stored.
  Each file contains the extracted JavaScript for one request. It will be
  created (including any parent directories) if it does not exist.
* `lint-result-path`: Where all ESLint results are stored. Each file contains
  the results for one file from above. These files have the same name as their
  JavaScript counterparts with `-linted` appended. For example, the results for
  `google.com-whatever.js` will be in `google.com-whatever-linted.js`.  It will
  be created (including any parent directories) if it does not exist.
* `database-path`: Path to the SQLite database file. If the file does not exist,
  it will be created.

Inside each JavaScript file (and ESLint result file), there is a comment that
identifies the URL and the referer. Using this information you can figure
out where this JavaScript came from and how to apply the results.

### Command Paths
The extension needs to know where it can run `eslint` and `js-beautify`
commands. This information is in the following keys:

* `linter-command`
* `jsbeautifier-command`

The git submodule [eslint-security][eslint-security] takes care of
installing these commands and the ESLint plugins. The commands will be located
in `eslint-security/node_modules/.bin/`.

On Windows be sure to point these to `eslint.cmd` and `js-beautify.cmd` and not
just `eslint` and `js-beautify`.

[eslint-security]: https://github.com/parsiya/eslint-security

### Highlight Requests
The extension can highlight requests in Burp's HTTP History. `"highlight" :true`
enables this behavior. This can help you quickly figure out which requests have
JavaScript.

* `cyan`: Requests that point to a JavaScript resource. E.g.,
  `https://example.net/whatever.js`.
* `yellow`: Requests that contain JavaScript but are not JavaScript files. These
  are mostly `text/html` files.

The default value is `false`.

### Process Requests Created by Specific Burp Tools
It's possible to tell the extension to only process requests/responses sent from
certain Burp tools. For example, if you do not want to process anything coming
from Proxy and are only interested in output from your own extension (or another
Burp tool like Repeater), you can set it.

This is controlled by the `process-tool-list` key in the config file. It
contains an array where each element is the **name of the tool**. This is the
result from the [IBurpExtenderCallbacks.getToolName][getToolName-doc] function.
The following table shows all available options.

| ToolFlag       | getToolName |
|----------------|-------------|
| TOOL_SUITE     | Suite       |
| TOOL_TARGET    | Target      |
| TOOL_PROXY     | Proxy       |
| TOOL_SPIDER    | Scanner     |
| TOOL_SCANNER   | Scanner     |
| TOOL_INTRUDER  | Intruder    |
| TOOL_REPEATER  | Repeater    |
| TOOL_SEQUENCER | Sequencer   |
| TOOL_DECODER   | null        |
| TOOL_COMPARER  | null        |
| TOOL_EXTENDER  | Extender    |

Default values are:

```json
"Proxy",
"Scanner",
"Repeater"
```

[getToolName-doc]: https://portswigger.net/burp/extender/api/burp/IBurpExtenderCallbacks.html#getToolName(int)

### Only Process Requests in Scope
By setting the `only-process-in-scope` key to `true`. The extension only
processes requests set in the scope tab. This useful when you are only
interested in JavaScript files in a specific scope.

The extension uses the [IBurpExtenderCallbacks.isInScope][isinscope-doc]
function to decide if a request is in scope.

Note: This setting is not retroactive. Setting this to `false` or changing the
scope does not go back and process all previous files that were received
earlier. The extension only process requests when they are received and does
look back in history.

[isinscope-doc]: https://portswigger.net/burp/extender/api/burp/IBurpExtenderCallbacks.html#isInScope(java.net.URL)

### Performance
linting and beautifying commands are computationally expensive. A single web
page could load a few dozen JavaScript files or a large vendored file. You can
configure the number of threads used by the extension to configure the load for
your machine.

`number-of-linting-threads` is the most important item in this section. You can
most likely keep the default values. If you are running Burp on a slow machine
or one without a lot of RAM, reduce this number.

Note that most concurrent operations use threadpools. Meaning if you set a low
number, nothing is lost and the work is queued. The results are also
stored in the database, so if you unload the extension (or close Burp) in the
middle of processing nothing is lost. Items can be processed when the
extension is loaded again.

* `number-of-linting-threads`: Number of concurrent thread beautifying and
  linting JavaScript. This is the most expensive operation. By default, the
  value of this key is `3`. Note that you can also stop processing using the
  `Process` toggle button in the extension interface.
* `number-of-request-threads`: Every request and response is processed in a
  separate thread. This element controls the number of concurrent request and
  response processing threads.
* `lint-timeout`: The maximum number of seconds for each beautifying and
  linting task. Increase this number if you are processing large JavaScript
  files.
* `maximum-js-size`: Files over this number (in KiloBytes) are not processed.
  `0` disables this setting. This is useful if you are dealing a lot of 3rd
  party libraries or vendor files on a slower machine or you are not interested
  in large files.
* `lint-task-delay`: Number of seconds to wait before reading new rows from the
  database and adding them to the linting threadpool. Increase this number if
  you are not dealing with a lot of JavaScript. An extension thread constantly
  reads from the database and adds the rows that are not processed to the
  linting threadpool. This is the number of the delay in seconds between reads.
* `update-table-delay`: Number of seconds to wait before updating the table in
  the extension tab. Increase this number if you are not processing a lot of
  JavaScript files.
* `threadpool-timeout`: Number of seconds to wait for the threadpool tasks to
  finish before shutdown. The threadpools are shutdown when a new config is
  loaded and when the extension is unloaded. Decrease this number if you are
  experimenting with new configurations or are testing the extension.

### Configuring JavaScript Detection
You can configure what responses are looked at. The default values do a great
job for most web applications. But if you have JavaScript in non-traditional
files/extensions/content-types/MIME types you can add them here.

From the extension's perspective, there are three kinds of request/response
pairs:

* "Pure" JavaScript: All of the content in the body of the response is
  JavaScript. E.g., js files.
* Embedded JavaScript: The response contains some JavaScript. E.g., HTML files.
* No JavaScript: The response does not have any JavaScript.

#### Pure JavaScript
All files with MIME types included in `js-mime-types` and URLs ending in
extensions in `javascript-file-extensions` are considered pure JavaScript. The
complete body of these responses will be stored in a file and linted.

Note: This is different from files that have embedded JavaScript like HTML
files. If your response body is not pure JavaScript, do not include them here.
Including these files in these settings will only result in parsing errors. For
these files see the [Embedded JavaScript](#embedded-javascript) section below.

Burp has two MIME type detection methods for responses:

* `getInferredMimeType()`
* `getStatedMimeType()`

These methods return `script` if Burp thinks the response is a JavaScript file.
It's not always accurate but it's usually correct. If you are looking to process
MIME types (returned by Burp) that are not in the default list (see the sample
config file). Add them to the end of the list in your extension config file.

The following URL lists all JavaScript MIME types (search for `text/javascript`
in the page). It appears that `text/javascript` is the most common.

* https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types

```json
"js-mime-types": [
  "application/javascript",
  "application/ecmascript",
  "application/x-ecmascript",
  "application/x-javascript",
  "text/javascript",
  "text/ecmascript",
  "text/javascript1.0",
  "text/javascript1.1",
  "text/javascript1.2",
  "text/javascript1.3",
  "text/javascript1.4",
  "text/javascript1.5",
  "text/jscript",
  "text/livescript",
  "text/x-ecmascript",
  "text/x-javascript",
  "script"
]
```

Any URL with extensions in `javascript-file-extensions` is considered pure
JavaScript. If you have extensions that have JavaScript, add them here.

```json
"javascript-file-extensions": [
  "js",
  "javascript"
],
```

#### Embedded JavaScript
The extension extracts the JavaScript in these responses. All text 
between `script` HTML tags is grabbed, beautified and ESLinted.

The extension detects these responses through their `Content-Type` headers. Any
content-type included in the `contains-javascript` item will be considered to
have embedded JavaScript.

```json
"contains-javascript": [
  "text/html",
  "application/xhtml+xml"
]
```

Note: Adding pure JavaScript responses here will result in their JavaScript not
detected. Because pure JavaScript files do not wrap their content in `script`
HTML tags.

### Removing Request Headers
The extension supports removing headers from requests. Any header included in
`removable-headers` will be removed from requests processed by the
extension.

This is useful for removing cache-control headers. Applications and browsers
usually try to re-use cached assets. If a cached asset is requested and these
headers are not removed, the response will be a [304 Not Modified][304-docs]
with no content. Such a response is useless to the extension.

Note: The extension does a good job of detecting duplicate resources and reusing
lint results. See the [technical-details.md](technical-details.md) file for
details.

[304-docs]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/304

### The Debug Flag
Setting `debug` to `true` will print diagnostics messages to the extension's
console. It's intended for troubleshooting and testing. The best way to use it
is to isolate a single request/response that is causing the error. Enable debug
and send the request in Repeater.
