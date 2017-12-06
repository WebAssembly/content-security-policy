# WebAssembly Content Security Policy

This proposal attempts to homogenize existing WebAssembly implementation's
handling of Content Security Policy (CSP).

It also attempts to extend CSP to better support WebAssemble use cases.

## Background: CSP Threat Model and Use Cases

This section describes the attacks that CSP is meant to protect
against. WebAssembly's handling of CSP should respect this threat model.

CSP, broadly, allows developers to control what resources can be loaded as part
of a site. These resources can include images, audio, video, or scripts. Loading
untrusted resources can lead to a variety of undesirable outcomes. Malicious
scripts could exfiltrate data from the site. Images could display misleading or
incorrect information. Fetching resources leaks information about the user to
untrusted third parties.

While these threats could be protected against in other ways, CSP allows a small
set of security experts to define a comprehensive policy in one place to prevent
accidentally loading untrusted resources into the site.

### Out of Scope Threats

* **Bugs in the browser**. We assume correct implementations of image decoders,
  script compilers, etc. CSP does not protect against malicious inputs that can,
  for example, trigger buffer overflows.
* **Resource exhaustion**. Computation performed by scripts uses memory and CPU
  time and can therefore cause a denial of service on the browser. Protecting
  against this is one reason site owners use CSP, but denial of service is not a
  first order consideration for CSP. Scripts are dangerous not because of their
  resource consumption but because of other effects that can cause.


## WebAssembly and CSP

A WebAssembly Instance is made up of the code, or Wasm bytes, and an import
object. The import object defines the capabilities of the instance, and
therefore the worst case security behavior. An instance with an empty import
object cannot cause any effects and is therefore safe to run. If it were
possible to vet the import object, it would be safe to create instances and run
from untrusted Wasm code because the behavior of the code would be bounded by
the capabilities of the import object. In practice, vetting an import object is
extremely difficult in JavaScript; it is easy to accidentally give access to the
global object.

CSP turns the problem around. Assuming unrestricted capabilities, what code is
the developer willing to run on their site? Thus for WebAssembly, CSP will be
used to define what sources for Wasm bytes are trusted to instantiate and run.


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
