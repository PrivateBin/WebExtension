/* TODO this is obviously a crappy algorithm for detecting PrivateBin */
if (document.title == "PrivateBin") {
	console.log("PrivateBin validator reporting for duty!");
	
	/*
	 * Given: 
	 * HTMLCollection elements containing <script> elements and \
	 * Object versionHashes containing a map of expected filename => integrity mapping
	 * return:
	 * - true if all scripts match
	 * - false if there is a non-matching script
	 * - a string if there is another problem
	 */
	var compareSignatures = function(elements, versionHashes) {
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

	var checkScriptElements = function(hashes) {
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

    var getBrowser = function() {
		if (typeof browser !== "undefined") {
			return browser;
		} else {
			return chrome;
		}
	}

	var storageErrorHandler = function(error) {
		console.log("Fetching hashes via XHR");
		var xhr = new XMLHttpRequest();
		xhr.open('GET', "https://gdr.name/privatebin_hashes.json");
		xhr.responseType = 'text';
        xhr.onload = function(e) {
			if (this.status == 200) {
				var jsonResponse = JSON.parse(this.response);
				/* TODO proper sanity check of the received file */
				/* TODO signature validation */
				if (typeof jsonResponse['hashes'] === 'undefined') {
					console.log(jsonResponse);
					window.alert("Received a fishy hashes file");
					return;
				}
				
				getBrowser().storage.local.set({"privatebin": jsonResponse});
				checkScriptElements(jsonResponse['hashes']);
			} else {
				window.alert("Could not retrieve hashes for PrivateBin");
			}
		};
		xhr.send();
	};

	var storageRetrievedHandler = function(item) {
		if (item && Object.getOwnPropertyNames(item).length > 0 && !getBrowser().runtime.lastError) {
			checkScriptElements(item['privatebin']['hashes']);
		} else {
			storageErrorHandler(null);
		}
	};

	getBrowser().storage.local.get("privatebin", storageRetrievedHandler);
}
