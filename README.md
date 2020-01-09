# ESLint-Burp (placeholder name)
Manual JavaScript Linting is a Bug.

A talk in the series `Manual (Application) Security is a Bug` or just `Manual Security is a Bug`.

## Add this to README
In the config file, the tool names from Burp's `getToolName` are as follows.

1. Not all tool flags return a name. Decoder and Comparer return null.
2. Spider and Scanner return the same. If you need to differentiate between the
   two, you should use tool flags.
3. Use `extender` if you are interested in extra requests that are made by your
   other extensions.

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

## Update Submodules

`git submodule update --init --recursive --remote` this pulls the latest revision of
all submodules.

## config
On Windows, remember to point to `.bin/eslint.cmd` and `.bin/js-beautify.cmd`.

Note that Windows supports forward slash as the path separator.

## Files

* [Research Notes](notes.md)
* ~~Creating Burp Extension UIs in Python~~
    * Not needed anymore, switching to Java.

## TODO
Add and update as we go on.

* [ ] Good Name
* [ ] Initial POC (see below)
* [ ] Add more from [Future Enhancements](#future-enhancements) or anything else here.

## Initial POC

1. Research how to detect scripts. See [Research Notes](notes.md).
2. Write something that detects scripts.
3. Add metadata to JS files.
    1. Something like a JSON object (commented out) that contains information
       about where this file came from (e.g., URL, referer etc).
4. Beautify JS files.
    1. Preferably in ~~Python~~ Java.
    2. Need to do some error handling here, our extracted JS might not have the
       correct syntax.
5. Run ESLint via the command line for a few high impact rules.
    1. Decide on the high impact rules.
    2. ~~https://github.com/parsiya/burputils will have a `runExternal` module to help?~~
    3. ~~Or not use Burputils and have an extension specific utils file.~~
6. Create Burp issues from the results.

## TODO
* [ ] 1. Filter based on `toolFlag`.

## Future Enhancements
Add and update as we go on.

* [ ] Filter by scope.
* [ ] Convert ESLint and the rule packages to binary?
    * [ ] Single binary like Go is nice.
    * [ ] Otherwise single eslint binary and rules can be provided as separate files (if that is possible).
* [ ] ESLint and beautifier Speed improvements.
    * [ ] Use a JS beautifier in a different language.
    * [ ] Use an ESLint parser in a different language? (is that possible).
* [ ] Dissect and extract js maps.
* [ ] Customize config.
    * [ ] Could be a bunch of UI checkboxes.
    * [ ] Support custom configs by pasting the JSON of the config file in the UI.
* [ ] Severity of issues.

## Far-into-the-future Enhancements

* [ ] Use an ESLint equivalent in a different language (does such a thing exist?)
* [ ] Create our own ESLint rules?
* [ ] ScanJS UI like system?
    * [ ] Or just reuse ScanJS?

