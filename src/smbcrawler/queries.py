ALL_QUERIES = dict(
    high_value_files="""
WITH RECURSIVE FullPath AS (
    -- Base case: select the root entries
    SELECT
        p.id,
        p.parent_id,
        p.content_hash,
        t.name AS target_name,
        s.name AS share_name,
        p.name AS path
    FROM
        path AS p
    JOIN
        target AS t ON p.target_id = t.name
    JOIN
        share AS s ON p.share_id = s.name
    WHERE
        p.high_value = 1

    UNION

    -- Recursive case: append parent paths
    SELECT
        p.id,
        p.parent_id,
        fp.content_hash,
        fp.target_name,
        fp.share_name,
        p.name || '\\' || fp.path AS path
    FROM
        path AS p
    JOIN
        FullPath AS fp ON p.id = fp.parent_id
)
-- Final selection from the recursive CTE, filtering for root nodes
SELECT DISTINCT
    target_name, share_name, path, content_hash
FROM
    FullPath
WHERE parent_id IS NULL
""",
    high_value_shares=(
        "SELECT name, 'target' AS target_id FROM Share WHERE high_value = True"
    ),
    secrets_with_paths="""
WITH RECURSIVE FullPath AS (
    -- Base case: select the root entries
    SELECT
        p.id,
        p.parent_id,
        p.content_hash,
        secret.secret,
        secret.line,
        secret.line_number,
        t.name AS target_name,
        s.name AS share_name,
        p.name AS path
    FROM
        secret AS secret
    JOIN
        path AS p ON p.content_hash = secret.content_hash
    JOIN
        target AS t ON p.target_id = t.name
    JOIN
        share AS s ON p.share_id = s.name

    UNION

    -- Recursive case: append parent paths
    SELECT
        p.id,
        p.parent_id,
        fp.content_hash,
        fp.secret,
        fp.line,
        fp.line_number,
        fp.target_name,
        fp.share_name,
        p.name || '\\' || fp.path AS path
    FROM
        FullPath AS fp
    JOIN
        path AS p ON p.id = fp.parent_id
)
-- Final selection from the recursive CTE
SELECT
    secret, line, line_number, target_name, share_name, path, content_hash
FROM
    FullPath
""",
    serialized_paths="""
WITH RECURSIVE FullPath AS (
    -- Base case: select the root entries
    SELECT
        p.id,
        p.parent_id,
        p.size,
        p.high_value,
        t.name AS target_name,
        s.name AS share_name,
        p.name AS full_path
    FROM
        path AS p
    JOIN
        target AS t ON p.target_id = t.name
    JOIN
        share AS s ON p.share_id = s.name
    WHERE
        p.parent_id IS NULL

    UNION

    -- Recursive case: append child paths
    SELECT
        p.id,
        p.parent_id,
        p.size,
        p.high_value,
        fp.target_name,
        fp.share_name,
        fp.full_path || '\\' || p.name AS full_path
    FROM
        path AS p
    JOIN
        FullPath AS fp ON p.parent_id = fp.id
)
-- Final selection from the recursive CTE
SELECT DISTINCT
    target_name, share_name, full_path, size, high_value
FROM
    FullPath

""",
    summary="""
SELECT 'number_targets' AS key, count(*) AS value FROM target
UNION ALL
SELECT 'number_targets_with_open_ports' AS key, count(*) AS value FROM target WHERE port_open = "1"
UNION ALL
SELECT 'number_targets_with_open_shares' AS key, count(DISTINCT target_id) AS value FROM share
UNION ALL
SELECT 'number_shares' AS key, count(*) AS value FROM share
UNION ALL
SELECT 'number_shares_listable_root' AS key, count(*) AS value FROM share WHERE read_level > 0
UNION ALL
SELECT 'number_shares_listable_root_as_guest' AS key, count(*) AS value FROM share WHERE read_level > 0 AND guest_access = '1'
UNION ALL
SELECT 'number_shares_writable' AS key, count(*) AS value FROM share WHERE write_access = "1"
UNION ALL
SELECT 'number_paths' AS key, count(*) AS value FROM path
UNION ALL
SELECT 'number_secrets' AS key, count(*) AS value FROM secret
UNION ALL
SELECT 'number_unique_secrets' AS key, count(DISTINCT secret) AS value FROM secret
UNION ALL
SELECT 'number_high_value_files' AS key, count(*) AS value FROM path WHERE high_value = '1'
UNION ALL
SELECT 'number_high_value_shares' AS key, count(*) AS value FROM share WHERE high_value = '1'
""",
)
