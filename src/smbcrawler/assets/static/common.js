function accessRow(row, columns, key) {
	return row[columns.indexOf(key)];
}

async function initDb() {
	const sqlPromise = initSqlJs({
		locateFile: (filename) => "static/sql-wasm.wasm",
	});

	const dataPromise = fetch("static/crawl.sqlite").then((res) =>
		res.arrayBuffer(),
	);

	const [SQL, buf] = await Promise.all([sqlPromise, dataPromise]);
	const db = new SQL.Database(new Uint8Array(buf));

	// Count rows of all tables
	const cols = Object.keys(document.columns);

	const queryRowCount = cols
		.map((c) => `SELECT '${c}' AS table_name, COUNT(*) AS row_count FROM ${c}`)
		.join(" UNION ALL ");

	const rowCount = db.exec(queryRowCount)[0];

	// Save results to document
	document.rowCount = {};
	for (const row of rowCount.values) {
		document.rowCount[row[0]] = row[1];
	}

	document.db = db;
}

function queryDb(table, opts) {
	// This function acts as the custom HTTP client for Grid.js
	return new Promise((resolve, reject) => {
		const cols = document.columns[table].map((c) => c.label).join(",");

		let where = "1=1";
		if (opts.url.keyword) {
			where = document.columns[table]
				.map((c) => `${c.label} LIKE '%${opts.url.keyword}%'`)
				.join(" OR ");
		}

		let order = `${document.columns[table][0].label} ASC`;
		if (opts.url.order) {
			order = opts.url.order
				.map((o) => `${o.order} ${o.direction || "ASC"}`)
				.join(", ");
		}

		let select = document.tableQueries[table];
		if (!select) {
			select = `SELECT ${cols} FROM ${table}`;
		}

		const query = `
${select}
WHERE ${where}
ORDER BY ${order}
LIMIT ${opts.url.limit}
OFFSET ${opts.url.page * opts.url.limit}`;
		// TODO: prevent SQLi?
		const rows = document.db.exec(query)[0];

		if (!rows) {
			reject();
		}

		resolve({
			data: rows.values,
			total: document.rowCount[table],
		});
	});
}

function makeGrid(table) {
	const grid = new gridjs.Grid({
		columns: document.columns[table],
		server: {
			data: (opts) => queryDb(table, opts),
		},
		pagination: {
			limit: 20,
			server: {
				data: (opts) => queryDb(table, opts),
				url: (prev, page, limit) => {
					const result = prev || {};
					result.page = page;
					result.limit = limit;
					return result;
				},
			},
		},
		search: {
			server: {
				url: (prev, keyword) => {
					const result = prev || {};
					result.keyword = keyword;
					return result;
				},
			},
		},
		sort: {
			multiColumn: true,
			server: {
				url: (prev, columns) => {
					if (!columns.length) return prev;

					const result = prev || {};

					const order = columns.map((c) => {
						return {
							order: document.columns[table][c.index].label,
							direction: c.direction === 1 ? "ASC" : "DESC",
						};
					});

					result.order = order;

					return result;
				},
			},
		},
		resizable: true,
		style: { td: { "font-family": "monospace" } },
	});
	return grid;
}

const boolFormatter = (cell) => (cell === 1 ? "Yes ✅" : "No ❌");

function convertArray(value) {
	return new TextDecoder().decode(value);
}

document.tableQueries = {
	path: document.queries.serialized_paths,
	secret: document.queries.secrets_with_paths,
};

document.columns = {
	target: [
		{ label: "id", name: "#" },
		{ label: "name", name: "Target" },
		{
			label: "port_open",
			name: "Port open",
			formatter: boolFormatter,
		},
		{ label: "instance_name", name: "Instance name" },
		{
			label: "listable_authenticated",
			name: "Listable (auth)",
			formatter: boolFormatter,
		},
		{
			label: "listable_unauthenticated",
			name: "Listable (no auth)",
			formatter: boolFormatter,
		},
	],
	share: [
		{ label: "id", name: "#" },
		{ label: "target_name", name: "Target" },
		{ label: "name", name: "Share" },
		{ label: "remark", name: "Remark" },
		{ label: "high_value", name: "High Value", formatter: boolFormatter },
		{ label: "auth_access", name: "Auth. access", formatter: boolFormatter },
		{ label: "guest_access", name: "Guest access", formatter: boolFormatter },
		{ label: "write_access", name: "Write access", formatter: boolFormatter },
		{ label: "read_level", name: "Read level" },
		{ label: "maxed_out", name: "Maxed out", formatter: boolFormatter },
	],
	path: [
		{ label: "id", name: "#" },
		{ label: "target_name", name: "Target" },
		{ label: "share_name", name: "Share" },
		{ label: "full_path", name: "Path" },
		{ label: "size", name: "Size" },
		{
			label: "high_value",
			name: "High Value",
			formatter: boolFormatter,
		},
	],
	// FIXME TODO search in secrets table not working
	secret: [
		{ label: "secret", name: "Secret" },
		{ label: "line", name: "Full line" },
		{ label: "target_name", name: "Target" },
		{ label: "share_name", name: "Share" },
		{ label: "path", name: "Path" },
		{
			label: "content_hash",
			name: "Content",
			formatter: (x) =>
				gridjs.html(
					`<a href="content/${convertArray(x)}" target="_blank">Open</a>`,
				),
		},
	],
};
