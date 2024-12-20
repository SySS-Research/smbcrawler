function convertArray(value) {
	return new TextDecoder().decode(value);
}

function processData(values) {
	const secretMap = new Map();
	const pathMap = new Map();

	for (const s of values) {
		const key = JSON.stringify([s.secret, s.line]);
		if (!secretMap.has(key)) {
			secretMap.set(key, []);
		}
		secretMap.get(key).push(`\\\\${s.target}\\${s.share}\\${s.path}`);
	}
	for (const [key, value] of secretMap.entries()) {
		const frozenSet = JSON.stringify([...new Set(value)].sort());
		if (!pathMap.has(frozenSet)) {
			pathMap.set(frozenSet, []);
		}
		pathMap.get(frozenSet).push(JSON.parse(key));
	}

	const result = Array.from(pathMap.entries()).map(([locations, values]) => ({
		values: values.map((s) => ({ secret: s[0], line: s[1] })),
		locations: JSON.parse(locations),
	}));

	return result;
}

function addItem(item, headline) {
	const template = document.getElementById("guide-template");
	const clone = template.content.cloneNode(true);
	const preElement = clone.querySelector(".secret-lines");
	const locationListElement = clone.querySelector(".locations ul");

	for (const s of item.values) {
		preElement.innerHTML += `${s.line.replace(
			s.secret,
			`<strong>${s.secret}</strong>`,
		)}\n`;
	}
	for (const l of item.locations) {
		const listItem = document.createElement("li");
		listItem.innerText = l;
		locationListElement.append(listItem);
	}

	clone.querySelector(".headline").innerText = headline;

	document.getElementById("guide").append(clone);
}

async function secretsCleanupGuideMain() {
	await initDb();
	const rows = document.db.exec(document.queries.secrets_with_paths)[0];
	const secrets = rows.values.map((row) => {
		return {
			secret: accessRow(row, rows.columns, "secret"),
			line: accessRow(row, rows.columns, "line"),
			path: accessRow(row, rows.columns, "path"),
			target: accessRow(row, rows.columns, "target_name"),
			share: accessRow(row, rows.columns, "share_name"),
		};
	});
	const data = processData(secrets);
	for (const [idx, item] of data.entries()) {
		addItem(item, `#${idx + 1}`);
	}
}
