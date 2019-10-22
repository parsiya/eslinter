# ESLint-Burp (placeholder name)
Manual JavaScript Linting is a Bug.

A talk in the series `Manual (Application) Security is a Bug` or just `Manual Security is a Bug`.

## Files

* [Research Notes](notes.md)

## TODO
Add and update as we go on.

* [ ] Good Name
* [ ] Initial POC (see below)
* [ ] Add more from [Future Enhancements](#future-enhancements) or anything else here.

## Initial POC

1. Research how to detect scripts. See [Research Notes](notes.md).
2. Write something that detects scripts.
3. Beautify JS files.
    1. Preferably in Python or a native binary in any language.
4. Run ESLint via the command line for a few high impact rules.
    1. Decide on the high impact rules.
    2. https://github.com/parsiya/burputils will have a `runExternal` module to help?
    3. Or not use Burputils and have an extension specific utils file.
5. Create Burp issues from the results.

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
* [ ] 