'use strict';
var gdr_gdr_name_pubkey = '[BUILD:GRD_KEY//TODO]'
// TODO: add pgp key here during build or read from file during execution if possible (inline is ugly)

// TODO: also put this into class and do not execute on every page load (which is done currently AFAIK)
keyring = new kbpgp.keyring.KeyRing();
kbpgp.KeyManager.import_from_armored_pgp({
    armored: gdr_gdr_name_pubkey
}, function(err, gdr) {
    if(!err) {
        keyring.add_key_manager(gdr);
    } else {
        console.log(err);
    }
});

// TODO: also puit into "class" and stuff, use function for PB detection to let it change
// TODO: this is obviously a crappy algorithm for detecting PrivateBin
if (document.title == "PrivateBin") {
    console.log("PrivateBin validator reporting for duty!");

    var storageRetrievedHandler = function(item) {
        var itemAge = (new Date().getTime() / 1000) - item['privatebin']['last_modified'];

        if (itemAge < 7*24*3600 && item && Object.getOwnPropertyNames(item).length > 0 && !Helper.getBrowser().runtime.lastError) {
            checkScriptElements(item['privatebin']['hashes']);
        } else {
            HashUpdater.runUpdate();
        }
    };

    Helper.getBrowser().storage.local.get("privatebin", storageRetrievedHandler);
}

/**
 * Helper - Useful helper functions, whcih are needed very often.
 *
 * @return {object} Methods: checkScriptElements
 */
var Helper = (function () {
    var me;

    /**
     * getBrowser - return browser object
     *
     * @return {object????}
     */
    me.getBrowser = function getBrowser() {
        if (typeof browser !== "undefined") {
            return browser;
        } else {
            return chrome;
        }
    };

    return me;
})();

/**
 * Verifier - Verifies a PrivateBin web page.
 *
 * @return {object} Methods: checkScriptElements
 */
var Verifier = (function () {
    var me;

    /**
     * compareHashes - compares the hashes of all script tags when given an
     * object with expected hashes
     *
     * @todo do not return string, needs better solution
     * @param {???} elements HTMLCollection elements containing <script> elements
     * @param {object} elements versionHashes map of expected filename => integrity mapping
     * @return {bool}
     */
    function compareHashes(elements, versionHashes) {
        var foundFiles = new Object();
        for (var i = 0; i < elements.length; i++) {
            var element = elements[i];
            var src = element.getAttribute("src");
            var integrity = element.getAttribute("integrity");

            if (src === null) {
                return "Found a rouge script tag without src";
            }

            if (integrity === null) {
                return "Found a script tag without integrity";
            }

            if (versionHashes[src] !== undefined) {
                if (versionHashes[src] != integrity) {
                    return false;
                } else {
                    foundFiles[src] = true;
                }
            } else {
                return false;
            }
        }

        /* All scripts on page match at this point, now check if no scripts are missing */
        for (var script_name in versionHashes) {
            if (foundFiles[script_name] === undefined) {
                return script_name + " missing";
            }
        }

        return true;
    };

    /**
     * compareAllHashes - compares all script tags on current page
     *
     * @param {object} hashes expected hashes array keyed by version number
     * @return {void}
     */
    me.checkScriptElements = function checkScriptElements(hashes) {
        var scriptElements = document.getElementsByTagName("script");
        var found = false;

        for (var version_number in hashes) {
            if (compareSignatures(scriptElements, hashes[version_number]) === true) {
                found = version_number;
                break;
            }
        }
        if (found !== false) {
            console.log("Found PrivateBin v" + found);
        } else {
            console.log("PrivateBin did not match any version");
            window.alert("It's not safe to use this PrivateBin instance, it may be serving malicious Javascript!");
        }
    };

    return me;
})();

/**
 * HashUpdater - Fetches officiasl/original hash list from the PrivateBin site.
 *
 * @todo save hashes offline
 * @return {object} Methods: updateHashes
 */
var HashUpdater = (function () {
    var me;
    var hashUrlKey = 'https://gdr.name/hashes.json.gpg';

    /**
     * runUpdate - Updates the hashes if necessary
     *
     */
    me.runUpdate = function() {
        console.log("Fetching new hashes via XHR");
        var xhr = new XMLHttpRequest();
        xhr.open('GET', hashUrl);
        xhr.responseType = 'text';
        xhr.onload = function(e) {
            if (this.status == 200) {
                kbpgp.unbox({
                    keyfetch: keyring,
                    armored: this.response,
                },
                // TODO: pass (private) function here instead of concenating this all
                function(err, literals) {
                    if (err != null) {
                        console.log(err);
                        window.alert("PGP signature check failed: " + err);
                    } else {
                        if (literals.length < 1) {
                            window.alert("Received an empty hashes file");
                            return;
                        }
                        var jsonResponse = JSON.parse(literals[0].toString());

                        /* Heavy sanity checking for the received JSON file */
                        // TODO: own part -> maybe in private method (in this "class")
                        if (typeof jsonResponse != 'object') {
                            window.alert("Received a malformed hashes JSON file: root element not an object");
                            return;
                        }

                        if (typeof jsonResponse['last_modified'] != 'number') {
                            window.alert("Received a malformed hashes JSON file: last_modified invalid");
                            return;
                        }

                        if (typeof jsonResponse['hashes'] != 'object') {
                            console.log(jsonResponse);
                            window.alert("Received a fishy hashes file");
                            return;
                        }

                        if (Object.getOwnPropertyNames(jsonResponse['hashes']).length < 1) {
                            console.log(jsonResponse);
                            window.alert("Received a malformed hashes JSON file: empty hashes object");
                            return;
                        }

                        for (var version in jsonResponse['hashes']) {
                            for (var scriptName in jsonResponse['hashes'][version]) {
                                if (typeof scriptName != 'string') {
                                    window.alert("Received a malformed hashes JSON file: found a non-string hashes key");
                                    return;
                                }
                                if (typeof jsonResponse['hashes'][version][scriptName] != 'string') {
                                    window.alert("Received a malformed hashes JSON file: found a non-string hashes value");
                                    return;
                                }
                            }
                        }

                        Helper.getBrowser().storage.local.set({"privatebin": jsonResponse});
                        HashUpdater.checkScriptElements(jsonResponse['hashes']);
                    }
                });
            } else {
                window.alert("Could not retrieve hashes for PrivateBin");
            }
        };
        xhr.send();
    };

    return me;
})();
