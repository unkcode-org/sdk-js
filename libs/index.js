"use strict";

import axios from "axios";
import cryptoJs from "crypto-js";
import utf8 from "crypto-js/enc-utf8.js";
import Base64 from "crypto-js/enc-base64.js";
import { getUnixTime } from "./modules/time.js";

const { MD5 } = cryptoJs;

function UNKApp({ name, secretKey, verifyLicense, verificationFail }) {
	this.name = name;
	this.token = MD5(secretKey);
	this.login = loginWithLicense;
	this.verify = verifyLicense;
	this.failCb = verificationFail;
}

/**
 * Initialize UNKCode app
 *
 * @param {Object} config Array with app configuration
 * @param {string} config.name The app name as it appears on https://unkcode.com/panel/dev/applications
 * @param {string} config.secretKey The app secret key
 * @param {boolean} config.verifyLicense Bool which indicates if application will run a verification routine to have knowledge about the license status when a user is logged
 * @param {function} config.verificationFail Callback that will be executed on license verifiaction fail
 * @returns {UNKApp} Object to access sdk functions.
 */

export const initializeApplication = ({ name, secretKey, verifyLicense, verificationFail }) => {
	if (!name || !secretKey || !verifyLicense || !verificationFail) throw new Error("[UNKCode][ERROR] All fields must be completed to initilize the application.");

	return new UNKApp({ name: name, secretKey: secretKey, verifyLicense: verifyLicense, verificationFail: verificationFail });
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
	const powRes = await axios({
		url: `https://unkcode.com/api/v1/verify/pow/${this.name}`,
		method: "POST",
	}).catch(() => {
		return false;
	});

	if (!powRes.data.message.includes("SUCN")) {
		return false;
	}

	let powKey = powRes.data.otherData + MD5(license + this.token).toString();

	let json = {
		token: powKey,
	};

	if (macAddress) {
		json.macHash = MD5(macAddress).toString();
	}

	json = JSON.stringify(json);

	const { data } = await axios({
		url: `https://unkcode.com/api/v1/verify/${this.name}/${license}`,
		method: "POST",
		headers: { "Content-Type": "application/json" },
		data: JSON.stringify({ data: Base64.stringify(utf8.parse(json)) }),
	});

	if (data.token === undefined) {
		return false;
	}

	let date = await getUnixTime();

	if (date.getUTCMinutes() >= 55 || date.getUTCMinutes() <= 5) {
		date.setTime(date.getTime() + 3600000);
	}

	if (MD5(powKey + date.getUTCHours() + this.token).toString() !== data.token) {
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
		await sleep(900000);
		let logged = await loginWithLicense({ license: lic, macAddress: macHash });
		if (!logged) {
			cb();
		}
	}
};
