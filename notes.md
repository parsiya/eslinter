# Research Notes
Static analysis of JavaScript through the ages:

* Script to detect DOM XSS
    * http://antisnatchor.com/Enumerate_potential_DOM-based_XSS_vulnerable_code

In the following blog post (2012), Ryan Dewhurst mentions that it would be nice to have JavaScript taint analysis for DOM XSS in Burp.

* https://blog.dewhurstsecurity.com/2012/07/19/staticburp-burp-suite-potential-dom-xss-analysis.html

The link to the extension does not work anymore.

Searching for ESLint + Burp on Twitter gets us a series of tweets by David Rook from 2015:

* https://twitter.com/davidrook/status/643907041363410944

Seems like he created an extension but never continued or released it.

----------

## How to detect JS in responses
Some ideas, including some from [DetectDynamicJS](https://github.com/luh2/DetectDynamicJS)

* https://github.com/luh2/DetectDynamicJS/blob/master/DetectDynamicJS.py#L229

```python
def isScript(self, requestResponse):
    """Determine if the response is a script"""
    try:
        response = requestResponse.getResponse()
    except:
        return False
    if not self.hasBody(response):
        return False
    responseInfo = self._helpers.analyzeResponse(response)
    body = response.tostring()[responseInfo.getBodyOffset():]
    first_char = body[0:1]
    mimeType = responseInfo.getStatedMimeType().split(';')[0]
    inferredMimeType = responseInfo.getInferredMimeType().split(';')[0]
    return (first_char not in self.ichars and
            ("script" in mimeType or "script" in inferredMimeType or
                self.hasScriptFileEnding(requestResponse) or self.hasScriptContentType(response)))
```

1. By extension, check for `js` and `json`.
    1. Why JSON? for maps?
    2. What about jsmaps? What are their extensions?
        1. `.js.map` or `.map`?
    3. Any other extensions? `pack`?
    4. Framework specific extensions?
        1. Angular
        2. React
        3. Add more
    5. [guessContentTypeFromName(string)](https://docs.oracle.com/javase/8/docs/api/java/net/URLConnection.html#guessContentTypeFromName-java.lang.String-)
2. How can we extract jsmaps and get the JS files?
    1. What are jsmaps?
    2. What is their structure?
3. By MIME Type of the response.
    1. IResponseInfo.getStatedMimeType: https://portswigger.net/burp/extender/api/burp/IResponseInfo.html#getStatedMimeType()
    2. IResponseInfo.getInferredMimeType: https://portswigger.net/burp/extender/api/burp/IResponseInfo.html#getInferredMimeType()
    3. Anything else?
4. What about scripts inside response (similar to what Burp does)
    1. Regex for `<script.*>(.*)</script>`?
    2. Where else can we have embedded scripts?
    3. Note on XHTML files, we might see stuff in CDATA tags.
5. How to create Burp extension UI in Python.
    1. Lots of examples for Burp extensions in Java
    2. Only a few in Python.
        1. Read those and learn.
        2. Make a blog post about it.

## Embedding JS in Python?

* https://github.com/sqreen/PyMiniRacer
* Related blog: https://blog.sqreen.com/embedding-javascript-into-python/
* 

## Hurdles

1. Handling large files?
    1. Beautifying and linting them will consume a lot of RAM. Let's assume we will run node with 4GBs of RAM.
    2. Do we have a size limit? Works for the POC but not in action.
    3. Split the files into chunks?
        1. Works if we are using a map that has separate JS files?
        2. For big files, use a parser and make chunks and the end of self-contained blocks?
            1. How do we figure this out?
        3. Drop standard stuff that we can recognize as 3rd party.
2. Performance issues
    1. Both ESLint and the beautifier are slow on large files and use a lot of RAM.
