const items_limit = 50;

function getTargets(limit, offset) {
	const query = `SELECT * FROM target WHERE listable_authenticated = 1 OR listable_unauthenticated = 1 ORDER BY name LIMIT ${offset}, ${limit + 1}`;
	const result = document.db.exec(query)[0];
	return result;
}

function getShares(target_id, limit, offset) {
	const query = `SELECT * FROM share WHERE target_id = '${target_id}' ORDER BY name LIMIT ${offset}, ${items_limit + 1}`;
	const result = document.db.exec(query)[0];
	return result;
}

function getPaths(targetId, shareId, limit, offset) {
	const query = `SELECT * FROM path WHERE target_id = '${targetId}' AND share_id = '${shareId}' AND parent_id IS NULL ORDER BY name LIMIT ${offset}, ${limit + 1}`;
	const result = document.db.exec(query)[0];
	return result;
}

function getSubPaths(parentId, limit, offset) {
	const query = `SELECT * FROM path WHERE parent_id = '${parentId}' ORDER BY name LIMIT ${offset}, ${limit + 1}`;
	const result = document.db.exec(query)[0];
	return result;
}

function addShowMore(parentNode) {
	const newNode = createNode("more", "Show more");
	parentNode.append(newNode);
}

function loadMore(evnt) {
	const showMoreNode = evnt.target.closest("div.node");
	const node = showMoreNode.previousElementSibling;

	let rows = null;
	let nodeFactory = null;

	if (node.dataset.table === "target") {
		rows = getTargets(items_limit, Number(node.dataset.index) + 1);
		nodeFactory = (rows, row) =>
			createNode(
				"target",
				accessRow(row, rows.columns, "name"),
				accessRow(row, rows.columns, "name"),
			);
	}

	if (node.dataset.table === "share") {
		rows = getShares(
			node.parentNode.closest("div.node").dataset.id,
			items_limit,
			Number(node.dataset.index) + 1,
		);
		nodeFactory = (rows, row) =>
			createNode(
				"share",
				accessRow(row, rows.columns, "name"),
				accessRow(row, rows.columns, "name"),
			);
	}

	if (node.dataset.table === "path") {
		if (node.parentNode.closest("div.node").dataset.table === "share") {
			rows = getPaths(
				node.parentNode.closest("div.node").parentNode.closest("div.node")
					.dataset.id,
				node.parentNode.closest("div.node").dataset.id,
				items_limit,
				Number(node.dataset.index) + 1,
			);
		} else {
			rows = getSubPaths(
				node.parentNode.closest("div.node").dataset.id,
				items_limit,
				Number(node.dataset.index) + 1,
			);
		}
		nodeFactory = (rows, path) =>
			createNode(
				"path",
				accessRow(path, rows.columns, "name"),
				accessRow(path, rows.columns, "id"),
				accessRow(path, rows.columns, "size") > 0,
			);
	}

	const nodesRemaining = checkRemaining(rows, items_limit);

	if (rows) {
		for (const row of rows.values) {
			showMoreNode.before(nodeFactory(rows, row));
		}
	}
	let children = node.closest("div.children");
	if (!children) {
		children = document.getElementById("tree-root");
	}
	orientateChildNodes(children);

	if (!nodesRemaining) {
		showMoreNode.remove();
	}
}

async function expandButton(evnt) {
	const node = evnt.target.closest("div.node");
	const childrenDiv = node.querySelector("div.children");

	if (node.dataset.expanded === "true") {
		evnt.target.innerText = "➕";
		node.dataset.expanded = "false";
		childrenDiv.replaceChildren();
	} else {
		let rows = null;
		let nodeFactory = null;

		if (node.dataset.table === "target") {
			rows = getShares(node.dataset.id, items_limit, 0);
			nodeFactory = (rows, share) =>
				createNode(
					"share",
					accessRow(share, rows.columns, "name"),
					accessRow(share, rows.columns, "name"),
				);
		}

		if (node.dataset.table === "share") {
			rows = getPaths(
				node.parentNode.closest("div.node").dataset.id,
				node.dataset.id,
				items_limit,
				0,
			);
			nodeFactory = (rows, path) =>
				createNode(
					"path",
					accessRow(path, rows.columns, "name"),
					accessRow(path, rows.columns, "id"),
					accessRow(path, rows.columns, "size") > 0,
				);
		}

		if (node.dataset.table === "path") {
			rows = getSubPaths(node.dataset.id, items_limit, 0);
			nodeFactory = (rows, path) =>
				createNode(
					"path",
					accessRow(path, rows.columns, "name"),
					accessRow(path, rows.columns, "id"),
					accessRow(path, rows.columns, "size") > 0,
				);
		}

		if (rows) {
			const nodesRemaining = checkRemaining(rows, items_limit);
			for (const v of rows.values) {
				const newNode = nodeFactory(rows, v);
				childrenDiv.appendChild(newNode);
			}
			if (nodesRemaining) {
				addShowMore(childrenDiv);
			}
			orientateChildNodes(childrenDiv);
		}

		evnt.target.innerText = "➖";
		node.dataset.expanded = "true";
	}
}

function createNode(type, body, id, isLeaf) {
	const icons = {
		share: "📁 ",
		target: "🖥️",
		path: "",
		more: "",
	};
	const template = document.getElementById("node-template");
	const clone = template.content.cloneNode(true);

	clone.querySelector("div.node").dataset.id = id;
	clone.querySelector("div.node").dataset.table = type;
	clone.querySelector("div.node").dataset.expanded = "false";
	clone.querySelector("div.type").dataset.type = type;
	clone.querySelector("div.type").innerText = icons[type];
	clone.querySelector("div.body").innerText = body;

	const button = clone.querySelector("button.expand-button");

	if (type === "more") {
		button.innerText = "…";
		button.addEventListener("click", loadMore);
	} else if (isLeaf && type === "path") {
		button.innerText = "📄";
		button.disabled = true;
	} else {
		button.addEventListener("click", expandButton);
	}
	return clone;
}

function orientateChildNodes(parentNode) {
	// Set level and index
	let i = 0;
	for (const node of parentNode.children) {
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

async function treeMain() {
	document.db = await initDb();
	const targets = getTargets(items_limit, 0);
	const nodesRemaining = checkRemaining(targets, items_limit);

	const treeRoot = document.getElementById("tree-root");
	const showMoreParent = treeRoot.parentNode.querySelector("div.show-more");

	for (const target of targets.values) {
		const node = createNode(
			"target",
			accessRow(target, targets.columns, "name"),
			accessRow(target, targets.columns, "name"),
		);
		treeRoot.appendChild(node);
	}
	if (nodesRemaining) {
		addShowMore(treeRoot);
	}
	orientateChildNodes(treeRoot);
}
