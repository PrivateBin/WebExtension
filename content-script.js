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

/* "browser is not defined" - okay, now i remember why i hate writing javascript.
//	var gettingStorage = browser.storage.local.get();
//
//	var storageErrorHandler = function(error) {
//		console.log("Fetching hashes via XHR");
//		var xhr = new XMLHttpRequest();
//		xhr.open('GET', "https://gdr.name/privatebin_hashes.json");
//		xhr.responseType = 'text';
//        xhr.onload = function(e) {
//			if (this.status == 200) {
//				var jsonResponse = JSON.parse(this.response);
//				/* TODO proper sanity check of the received file */
//				/* TODO signature validation */
//				if (jsonResponse['hashes'] !== undefined) {
//					window.alert("Received a fishy hashes file");
//					return;
//				}
//				
//				storage.local.set(jsonResponse);
//				checkScriptElements(jsonResponse);
//			} else {
//				window.alert("Could not retrieve hashes for PrivateBin");
//			}
//		};
//		xhr.send();
//	};
//
//	var storageRetrievedHandler = function(item) {
//		if (item) {
//			checkScriptElements(item);
//		} else {
//			storageErrorHandler(null);
//		}
//	};
//
//	gettingStorage.then(storageErrorHandler, storageRetrievedHandler);

	var storedHashes = {
		"last_modified": 1480535797,
		"hashes": {
			"1.0": {
				"js/base64-2.1.9.js": "sha512-rbqAby7hObftbEoGQzkhUbEh5YkUn2MtekTLs4btvo2oly4CZ3DxhJzEh0u/rNzS54tcJdqi5Ug1ruugEd2U1g==",
				"js/bootstrap-3.3.5.js": "sha512-/W33QnLmSAP1fwINS9iXgB6s/VOIG9GVdIuIYaUtbSvKPMv5S08PtT3PqnT2WjwBgB8DFeDN2nqJroqQYF7SwQ==",
				"js/jquery-1.11.3.js": "sha512-xAERw8wHVOkM9x9y9/FvQ7g1t+gIQj39mfkN1Rd1OLcC5k/x2e6NO8hq6qEbb3oO+CYYTjVLFiFYg5/7ddF0zA==",
				"js/prettify.js?1.0": "sha512-m8iHxoN+Fe12xxFwWNdY/TS4KoFntHp29qY0xUzBnPd0bkKMOR/dFhEdTWydpt0b/fIXyhB+znGYUvgjfJ2RzQ==",
				"js/privatebin.js?1.0": "sha512-Jx4qD49amdzpNe9FLtxLO84Xt5LZeQ2PGaM0I9UCS2Kr4xhrnFyvP+0hrLIMgDTwjWFDpTSCoDHuj0SHzuqXuQ==",
				"js/rawdeflate-0.5.js": "sha512-tTdZ7qMr7tt5VQy4iCHu6/aGB12eRwbUy+AEI5rXntfsjcRfBeeqJloMsBU9FrGk1bIYLiuND/FhU42LO1bi0g==",
				"js/rawinflate-0.3.js": "sha512-g8uelGgJW9A/Z1tB6Izxab++oj5kdD7B4qC7DHwZkB6DGMXKyzx7v5mvap2HXueI2IIn08YlRYM56jwWdm2ucQ==",
				"js/showdown-1.4.1.js": "sha512-Kbz1FIlDnqUJu/3yW8H8USzURA3JuUqSKRwz13lM4kWt6C0n6s4tjl81PCfnWtE4gBIzyj5uGePcfUyotk/icw==",
				"js/sjcl-1.0.4.js": "sha512-BqVQ8GgWfMCcdsDuP6Ggm1BV7+mmoWH3PC4UqcYpEKSdEq1rthy6NUsa6gu5sydewbi/ilI3E3ohdCxlPPF9ww=="
			}
		}
	};
	checkScriptElements(storedHashes['hashes']);
}
