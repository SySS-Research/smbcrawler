const items_limit = 600;
const labels = {
	id: "#",
	target_id: "Target",
	name: "Share",
	remark: "Remark",
	high_value: "High Value",
	auth_access: "Auth. access",
	guest_access: "Guest access",
	write_access: "Write access",
	read_level: "Read level",
	maxed_out: "Maxed Out",
};

async function expandButton(evnt) {
	const node = evnt.target.closest("div.node");

	document.db = await initDb();

	if (node.dataset.table === "target") {
		const query = `SELECT * FROM share WHERE target_id = '${node.dataset.id}' ORDER BY name LIMIT ${items_limit + 1}`;
		const shares = document.db.exec(query)[0];
		if (shares) {
			for (const share of shares.values) {
				const newNode = createNode(
					"share",
					accessRow(share, shares.columns, "name"),
					accessRow(share, shares.columns, "name"),
				);
				// TODO fix this
			}
		}
	}

	console.log(node.dataset.expanded, evnt.target.innerText);
	if (node.dataset.expanded === "true") {
		evnt.target.innerText = "➖";
		node.dataset.expanded = "false";
	} else {
		evnt.target.innerText = "➕";
		node.dataset.expanded = "true";
	}
}

function createNode(type, body, id) {
	const template = document.getElementById("node-template");
	const clone = template.content.cloneNode(true);
	clone.querySelector("div.node").dataset.id = id;
	clone.querySelector("div.node").dataset.table = type;
	clone.querySelector("div.node").dataset.expanded = "false";
	clone.querySelector("div.type").dataset.type = type;
	clone.querySelector("div.body").innerText = body;
	clone
		.querySelector("button.expand-button")
		.addEventListener("click", expandButton);
	return clone;
}

function orientateChildNodes(parentNode) {
	let i = 0;
	for (const node of parentNode.children) {
		// Set level and index
		if (parentNode.dataset.level) {
			node.dataset.level = Number(parentNode.dataset.level) + 1;
		} else {
			node.dataset.level = 0;
		}
		node.dataset.index = i++;
	}
}

function checkRemaining(array, limit) {
	let result = false;
	if (array.values.length > limit) {
		result = true;
		array.values.pop();
	}
	return result;
}

async function tree_main() {
	document.db = await initDb();
	const targets = document.db.exec(
		`SELECT * FROM target ORDER BY name LIMIT ${items_limit + 1}`,
	)[0];

	const nodesRemaining = checkRemaining(targets.values, items_limit);

	const treeRoot = document.getElementById("tree-root");

	for (const target of targets.values) {
		const node = createNode(
			"target",
			accessRow(target, targets.columns, "name"),
			accessRow(target, targets.columns, "name"),
		);
		const newNode = treeRoot.appendChild(node);
	}
	orientateChildNodes(treeRoot);

	if (nodesRemaining) {
		const template = document.getElementById("node-expand-template");
		const clone = template.content.cloneNode(true);
		treeRoot.append(node);
	}
}
