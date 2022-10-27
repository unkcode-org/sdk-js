import axios from "axios";

export const getUnixTime = async () => {
	const { data } = await axios({
		url: "https://unkcode.com/api/v1/unixtime",
	});

	return new Date(data * 1000);
};
