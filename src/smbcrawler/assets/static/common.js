async function initDb() {
	const sqlPromise = initSqlJs({
		locateFile: (filename) => "static/sql-wasm.wasm",
	});
	const dataPromise = fetch("static/crawl.sqlite").then((res) =>
		res.arrayBuffer(),
	);
	const [SQL, buf] = await Promise.all([sqlPromise, dataPromise]);
	const db = new SQL.Database(new Uint8Array(buf));
	return db;
}

function accessRow(row, columns, key) {
	return row[columns.indexOf(key)];
}
