# WebAssembly Content Security Policy

This proposal attempts to homogenize existing WebAssembly implementation's
handling of Content Security Policy.

It also attempts to extend CSP to better support WebAssemble use cases.

## Behavior of Current Implementations

All implementations currently permit all the WebAssembly operations they
support if there is no Content-Security-Policy specified.

All implementations currently permit all the WebAssembly operations they
support if there is a Content-Security-Policy specified
and `script-src` includes the 'unsafe-eval' directive.

Implementations vary as to which WebAssembly operations are allowed
if there is a Content-Security-Policy specified and
`script-src` does not include the 'unsafe-eval' directive.
The following table describes which operations are allowed in this case:

Operation | Chrome | Safari | Firefox | Edge
--- | --- | --- | --- | --- 
WebAssembly.validate | yes | yes | yes | yes
new WebAssembly.Module | no | yes | yes | yes
WebAssembly.compile | no | yes | yes | yes
WebAssembly.compileStreaming | no | yes | yes | yes
WebAssembly.instantiate | no | no | yes | yes
WebAssembly.instantiateStreaming | no | no | yes | yes
new WebAssembly.CompileError | yes | yes | yes | yes
new WebAssembly.LinkError | yes | yes | yes | yes
new WebAssembly.Table | yes | no | yes | yes
new WebAssembly.Memory | yes | no | yes | yes

The type of exception thrown when one of the above operations is disallowed
also varies by implementation.
This table lists the exception type for each implementation:

Browser | Thrown if disallowed
--- | --
Chrome | WebAssembly.CompileError: Wasm code generation disallowed in this context
Safari | EvalError
Firefox | N/A
Edge | ??

For references here is how each brower handles eval():

Browser | Thrown if disallowed
--- | --
Chrome | EvalError
Safari | EvalError
Firefox | Disallows script (uncatchable)
Edge | ??


## Proposed Homogenization of Existing Behavior

Motivating Principles:

* Be conservative about what is allowed.
* Allow operations which cannot be origin bound within
  the current API surface (Chrome's behavior).
   * Allow Memory and Table objects, because they are tied to
     the current origin,
     will be needed when compilation / instantiation is origin bound,
     have no parameters allowing an explicit origin.
   * Disallow compilation, as it can be used to exercise WebAssembly
     code compilation if an injection attack is present.
* Throw an EvalError (Safari's behavior), as this is what both
  Chrome and Safari do for eval(). NOTE: Firefox's behavior is even more
  conservative, but this might be challenging for others as it is more
  strict than for eval().

This table describes which operations should be allowed when
there is a Content-Security-Policy specified and
`script-src` does not include the 'unsafe-eval' directive:

Operation | Result
--- | ---
WebAssembly.validate | yes
new WebAssembly.Module | no
WebAssembly.compile | no
WebAssembly.compileStreaming | no
WebAssembly.instantiate | no
WebAssembly.instantiateStreaming | no
new WebAssembly.CompileError | yes
new WebAssembly.LinkError | yes
new WebAssembly.Table | yes
new WebAssembly.Memory | yes


## Proposed 'wasm-eval' Directive

WebAssembly compilation is less prone to being spoofed in the way
JavaScript is. Further, WebAssembly has an explicitly specified scope,
further reducing the likelihood of injection attacks.

While origin bound / known hash operations are always safer,
it is useful to have a mechanism to allow WebAssembly content
in a CSP policy that would otherwise disallow it, without being
required to also allow JavaScript eval().

NOTE: Providing a directive to allow JavaScript eval() without WebAssembly
doesn't seem immediately useful, and so has been left out intentionally.

We propose:
* Allow the 'wasm-eval' directive under each directive that currently
  supports 'unsafe-eval' (this is currently all directives because
  directives can defer to each other).
* For the `script-src` directive (directly or by reference),
  interpret 'wasm-eval' to mean
  that all WebAssembly operations should be allowed.
  (Without allowing eval()).


## Proposed Origin Bound Permission

In order to make WebAssembly more useful within the spirit of CSP,
we should permit `Response` objects to carry trusted origin information.
This will allow compilation and instantiation of WebAssembly
in a natural way within a CSP.

Proposed Changes:
* Response.url will be "hardened" to allow it (or it with a taint track bit)
  to be trusted to carry information regarding the origin of a fetch
  response.
* An immutable opaque bit mimeTypeWasm will be added to Response to capture
  whether the original Response had mime type 'application/wasm'.
   * Question: Does this interfere with service worker?
* WebAssembly compilation / instantiation requests that would
  be allowed if they were script src's for non-inline JavaScript
  which also have mimeTypeWasm,
  will also be allowed for WebAssembly.
   * This applies to hashes, or to origin whitelisting.
* This sub-proposal only affects WebAssembly.compileStreaming
  and WebAssembly.instatiateStreaming
  
### Total Behavior

The desired end state with both of these looks something like this:

Operation | default | unsafe-eval | wasm-eval | unsafe-eval + wasm-eval | w/ SRI ok | w/o SRI bad
--- | --- | --- | --- | -- | -- | --
WebAssembly.validate | allow | disallow | allow | allow | N/A | N/A
new WebAssembly.Module | allow | allow if from instantiateCompile | allow | allow | allow if from instantiateCompile | disallow if from instantiateCompile
WebAssembly.compile | allow | disallow | allow | allow | N/A | N/A
WebAssembly.compileStreaming | based on SRI | based on SRI | based on SRI | based on SRI | allow | disallow
WebAssembly.instantiate | allow | allow if from instantiateCompile | allow | allow | allow if from instantiateCompile | disallow if from instantiateCompile
WebAssembly.instantiateStreaming | based on SRI | based on SRI | based on SRI | based on SRI | allow | disallow
new WebAssembly.CompileError | allow | allow | allow | allow | allow | allow
new WebAssembly.LinkError | allow | allow | allow | allow | allow | allow
new WebAssembly.Table | allow | allow | allow | allow | allow | allow
new WebAssembly.Memory | allow | allow | allow | allow | allow | allow

### Examples

```
Content-Security-Policy: script-src 'self';

WebAssembly.compileStreaming(fetch('/foo.wasm'));  // OK
WebAssembly.instantiateStreaming(fetch('/foo.wasm')); // OK
WebAssembly.compileStreaming(fetch('/foo.js'));  // BAD: mime type
WebAssembly.instantiateStreaming(fetch('/foo.js')); // BAD: mime type
WebAssembly.compileStreaming(fetch('http://yo.com/foo.wasm'));  // BAD: cross origin
WebAssembly.instantiateStreaming(fetch('http://yo.com/foo.wasm')); // BAD: cross origin
```

```
Content-Security-Policy: script-src http://yo.com;

WebAssembly.compileStreaming(fetch('http://yo.com/foo.wasm'));  // OK
WebAssembly.instantiateStreaming(fetch('http://yo.com/foo.wasm')); // OK
```

```
Content-Security-Policy: script-src 'sha256-123...456';

WebAssembly.compileStreaming(fetch('http://baz.com/hash123..456.wasm'));  // OK
WebAssembly.instantiateStreaming(fetch('http://baz.com/hash123..456.wasm')); // OK
```
