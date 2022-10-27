import axios from "axios";
import cryptoJs from "crypto-js";
import utf8 from "crypto-js/enc-utf8.js";
import Base64 from "crypto-js/enc-base64.js";
import { getUnixTime } from "./modules/time.js";

const { MD5 } = cryptoJs;

function UNKApp({ name, secretKey }) {
	this.name = name;
	this.token = MD5(secretKey);
	this.login = loginWithLicense;
}

export const initializeApplication = ({ name, secretKey }) => {
	return new UNKApp({ name: name, secretKey: secretKey });
};

async function loginWithLicense({ license, macAddress }) {
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

	let json = JSON.stringify({
		token: powKey,
		macHash: MD5(macAddress).toString(),
	});

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
		date.setTime(date.getTime() + 60 * 60 * 1000);
	}

	if (MD5(powKey + date.getUTCHours() + this.token).toString() === data.token) {
		return true;
	}

	return false;
}
