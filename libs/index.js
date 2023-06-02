"use strict";

import axios from "axios";
import cryptoJs from "crypto-js";
import utf8 from "crypto-js/enc-utf8.js";
import Base64 from "crypto-js/enc-base64.js";

const { MD5 } = cryptoJs;

function AppInterface({ name, secretKey, verifyLicense, verificationFail }) {
	this.name = name;
	this.token = secretKey;
	this.login = loginWithLicense;

	this.regularVerification = verifyLicense;
	this.failedVerificationCallback = verificationFail;
}

/**
 * Initialize UNKCode app
 *
 * @param {Object} config Array with app configuration
 * @param {string} config.name The app name as it appears on https://unkcode.com/panel/dev/applications
 * @param {string} config.secretKey Application secret key retrieved by unkcode
 * @param {boolean} config.verifyLicense Run a verification routine to have knowledge about the license status when a user is logged (disabled by default)
 * @param {function} config.verificationFail Callback that will be executed on license verifiaction fail
 * @returns {AppInterface} Object to access sdk functions.
 */

export const UNKCode = ({ name, secretKey, verifyLicense = false, verificationFail }) => {
	if (!name || !secretKey || !verificationFail) throw new Error("[-] All fields must be completed to initilize unkcode application interface.");

	return new AppInterface({ name: name, secretKey: secretKey, verifyLicense: verifyLicense, verificationFail: verificationFail });
};

/**
 * Signin user to app using UNKCode's lincese and if required the macAdress
 *
 * @param {Object} config Array with needed data to login
 * @param {string} config.license The user license
 * @param {string} config.macAddress The user macAdress. Only in case that app config requires it
 * @returns {boolean} bool value of success
 */
async function loginWithLicense({ license, macAddress = undefined }) {
	const authRes = await axios({
		url: `https://unkcode.com/api/v1/verify/${this.name}`,
		method: "POST",
		headers: { "Content-Type": "application/json" },
		data: JSON.stringify({
			data: Base64.stringify(
				utf8.parse(
					JSON.stringify({
						auth: MD5(this.token).toString(),
					})
				)
			),
		}),
	}).catch(() => {
		return false;
	});

	if (!authRes.data.message.includes("SUCN")) {
		return false;
	}

	let verifyBodyParms = {
		token: authRes.data.token,
	};

	if (macAddress) {
		verifyBodyParms.macHash = MD5(macAddress).toString();
	}

	const { data } = await axios({
		url: `https://unkcode.com/api/v1/verify/${this.name}/${license}`,
		method: "POST",
		headers: { "Content-Type": "application/json" },
		data: JSON.stringify({
			data: Base64.stringify(utf8.parse(JSON.stringify(verifyBodyParms))),
		}),
	});

	if (!data.message.includes("SUCN")) {
		return false;
	}

	if (this.verify) {
		createVerificationRutine(license, macAddress, this.failCb);
	}

	return true;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const createVerificationRutine = async (lic, macHash, cb) => {
	while (true) {
		await sleep(20000);
		console.log("routine executed");
		let logged = await loginWithLicense({ license: lic, macAddress: macHash });
		if (!logged) {
			cb();
		}
	}
};
