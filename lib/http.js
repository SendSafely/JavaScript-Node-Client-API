// SendSafely/lib/http.js
//
// Thin adapter that mimics the surface of $.ajax used by SendSafely (and only
// that surface) using Node's native fetch (built on undici), then exposes a
// jqXHR-shaped object so existing callers using `.done()` / `.fail()` keep
// working unchanged.
//
// Parity contract (verified against api.jquery.com and Node 24 fetch behavior
// empirically):
//   - timeout option: emulated via `signal: AbortSignal.timeout(ms)` (Node ≥17.3)
//   - retry: NOT enabled (jQuery's `retryCount` was a no-op; preserve that)
//   - X-Requested-With: 'XMLHttpRequest' is added automatically by jQuery so
//     consumer servers may filter on it; we set it explicitly here
//   - Body is consumed as text() so the existing `if (typeof data === 'string')
//     data = JSON.parse(data)` defensive parse in processAjaxData continues
//     to handle JSON responses transparently
//   - Error path: failure callback receives `(xhr, status, error)` where only
//     `error.message` is consumed by callers — `extractMessage` unwraps
//     `err.cause` so the substantive reason (ECONNREFUSED / ENOTFOUND / etc.)
//     surfaces in the message rather than the generic "fetch failed" wrapper
//   - 4xx / 5xx responses route to .fail() (same as jQuery)

// Native fetch errors nest the substantive cause under .cause for network
// failures (TypeError "fetch failed" wraps Error with code ECONNREFUSED etc.),
// while AbortSignal.timeout produces a TimeoutError with the message directly
// on the top-level error (no .cause). Walk both shapes — exactly one level
// of unwrapping, matching the error-message shape consumers were already
// receiving via make-fetch-happen on main.
function extractMessage(err) {
    if (!err) return 'unknown error';
    if (err.cause && err.cause.message) return err.cause.message;
    return err.message || String(err);
}

function ajax(opts) {
    const headers = {
        'X-Requested-With': 'XMLHttpRequest'
    };
    if (opts.headers) {
        for (const k of Object.keys(opts.headers)) {
            headers[k] = opts.headers[k];
        }
    }
    if (opts.contentType) {
        headers['Content-Type'] = opts.contentType;
    }

    const init = {
        method: opts.type || 'GET',
        headers
    };
    if (opts.timeout != null) {
        init.signal = AbortSignal.timeout(opts.timeout);
    }
    if (opts.data != null) {
        init.body = opts.data;
    }

    const promise = (async () => {
        let response;
        try {
            response = await fetch(opts.url, init);
        } catch (err) {
            // Network / timeout error — surface substantive reason in .message
            const wrapped = new Error(extractMessage(err));
            wrapped.code = (err.cause && err.cause.code) || err.code;
            wrapped.cause = err;
            throw wrapped;
        }

        const body = await response.text();
        if (!response.ok) {
            const err = new Error('HTTP ' + response.status);
            err.status = response.status;
            err.responseText = body;
            throw err;
        }
        return body;
    })();

    return makeJqXhr(promise);
}

// jQuery 3.x semantics for consumer callback throws: an exception inside a
// .done() or .fail() handler becomes an async uncaught exception, NOT a
// rejected deferred and NOT a silent swallow.  `setImmediate(() => { throw e; })`
// produces the equivalent in Node.  Without this, a throw inside `fn(data)`
// (e.g. `JSON.parse` on malformed body inside `processAjaxData`) would reject
// the inner `.then` promise, producing an unhandledRejection that Node ≥15
// elevates to a process crash.
function rethrowAsync(e) {
    setImmediate(function () { throw e; });
}

function makeJqXhr(promise) {
    // jQuery semantics: .done fires only on fulfillment, .fail only on
    // rejection.  We attach both handlers via the two-arg `.then` so the
    // original promise's rejection is always consumed — no dead-letter
    // rejections.  Consumer callbacks are wrapped in try/catch so their
    // throws surface asynchronously (jQuery 3 behavior) instead of as
    // unhandled promise rejections.
    const obj = {
        done(fn) {
            promise.then(function (data) {
                if (typeof fn !== 'function') return;
                try { fn(data); }
                catch (e) { rethrowAsync(e); }
            }, function () { /* swallow: .fail handles it */ });
            return obj;
        },
        fail(fn) {
            promise.then(function () { /* swallow: .done handles it */ }, function (err) {
                if (typeof fn !== 'function') return;
                try { fn(null, 'error', err); }
                catch (e) { rethrowAsync(e); }
            });
            return obj;
        },
        then(onFulfilled, onRejected) {
            return promise.then(onFulfilled, onRejected);
        },
        catch(onRejected) {
            return promise.catch(onRejected);
        }
    };
    return obj;
}

module.exports = { ajax };
