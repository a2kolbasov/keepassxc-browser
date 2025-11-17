'use strict';

const httpAuth = {};

/** @typedef {{ credential?: { user: string, password: string } }} RequestAuxData */
/** @typedef {{ name: string, value: string }} RequestHeader */

/** @type {Map<number, RequestAuxData>} */
httpAuth.requests = new Map();


httpAuth.init = function() {
    let handleAuthRequest = httpAuth.handleRequestPromise;
    let authRequestBlockingType = 'blocking';

    if (!page.isFirefox) {
        handleAuthRequest = httpAuth.handleRequestCallback;
        authRequestBlockingType = 'asyncBlocking';
    }

    if (browser.webRequest.onAuthRequired.hasListener(handleAuthRequest)) {
        browser.webRequest.onAuthRequired.removeListener(handleAuthRequest);
        browser.webRequest.onSendHeaders.removeListener(httpAuth.handleSendRequest);
        browser.webRequest.onCompleted.removeListener(httpAuth.requestCompleted);
        browser.webRequest.onErrorOccurred.removeListener(httpAuth.requestError);
    }

    // Only intercept http auth requests if the option is turned on.
    if (page.settings.autoFillAndSend) {
        const opts = { urls: [ '<all_urls>' ] };

        browser.webRequest.onAuthRequired.addListener(handleAuthRequest, opts, [ authRequestBlockingType ]);
        browser.webRequest.onSendHeaders.addListener(httpAuth.handleSendRequest, opts, ['requestHeaders']);
        browser.webRequest.onCompleted.addListener(httpAuth.requestCompleted, opts);
        browser.webRequest.onErrorOccurred.addListener(httpAuth.requestError, opts);
    }
};

httpAuth.requestError = function(details) {
    httpAuth.requests.delete(details.requestId);
}

httpAuth.requestCompleted = function(details) {
    const requestAux = httpAuth.requests.get(details.requestId);
    if (requestAux === undefined) return;
    httpAuth.requests.delete(details.requestId);

    if (requestAux.credential) {
        // TODO ask user about saving
        console.trace(requestAux.credential);
    }
};

httpAuth.handleSendRequest = function(details) {
    const requestAux = httpAuth.requests.get(details.requestId);
    if (requestAux === undefined) return;

    /** @type {RequestHeader[]} */
    const requestHeaders = details.requestHeaders;
    const headerValue = requestHeaders.find(header => header.name === 'Authorization')?.value;
    if (!headerValue) return;

    const [scheme, base64Credential] = headerValue.split(' ', 2);
    if (scheme !== 'Basic') return;

    const decodedCredential = new TextDecoder('UTF-8').decode(
        Uint8Array.from(atob(base64Credential), c => c.charCodeAt(0))
    );

    // password can also contain `:`, we need the first one
    const separatorIndex = decodedCredential.indexOf(':');
    const user = decodedCredential.slice(0, separatorIndex);
    const password = decodedCredential.slice(separatorIndex + 1);

    requestAux.credential = { user, password };
}

httpAuth.handleRequestPromise = function(details) {
    return new Promise((resolve, reject) => {
        httpAuth.processPendingCallbacks(details, resolve, reject);
    });
};

httpAuth.handleRequestCallback = function(details, callback) {
    httpAuth.processPendingCallbacks(details, callback, callback);
};

httpAuth.retrieveCredentials = async function(tabId, url, submitUrl) {
    return await keepass.retrieveCredentials(tabId, [ url, submitUrl, false, true ]).catch((err) => {
        logError('httpAuth.retrieveCredentials error: ' + err);
        return Promise.reject();
    });
};

httpAuth.processPendingCallbacks = async function(details, resolve, reject) {
    if (httpAuth.requests.has(details.requestId) || !page.tabs[details.tabId]) {
        reject({ cancel: false });
        return;
    }

    httpAuth.requests.set(details.requestId, {});

    if (details.challenger) {
        // Non-HTTP proxies are possible with PAC scripts, while currently only
        // Firefox provides info about the proxy protocol used [1].
        // [1] https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/onAuthRequired
        const scheme = details.proxyInfo ? details.proxyInfo.type : 'http';
        details.proxyUrl = scheme + '://' + details.challenger.host;
    }

    details.searchUrl = (details.isProxy && details.proxyUrl) ? details.proxyUrl : details.url;

    const logins = await httpAuth.retrieveCredentials({ 'id': details.tabId }, details.searchUrl, details.searchUrl);
    httpAuth.loginOrShowCredentials(logins, details, resolve, reject);
};

httpAuth.loginOrShowCredentials = function(logins, details, resolve, reject) {
    // At least one login found --> use first to login
    if (logins.length > 0 && page.settings.autoFillAndSend) {
        if (logins.length === 1) {
            resolve({
                authCredentials: {
                    username: logins[0].login,
                    password: logins[0].password
                }
            });
        } else {
            if (page.settings.showNotifications) {
                showNotification(tr('multipleCredentialsDetected'));
            }
            kpxcEvent.onHTTPAuthPopup({ 'id': details.tabId }, { 'logins': logins, 'url': details.searchUrl, 'resolve': resolve });
        }
    } else {
        logError('No logins found for HTTP Basic Auth.');
        reject({ cancel: false }); // No logins found
    }
};
