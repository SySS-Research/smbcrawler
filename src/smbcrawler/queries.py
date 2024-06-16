high_value_files = """
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
"""

high_value_shares = (
    "SELECT name, 'target' AS target_id FROM Share WHERE high_value = True"
)

secrets_with_paths = """
WITH RECURSIVE FullPath AS (
    -- Base case: select the root entries
    SELECT
        p.id,
        p.parent_id,
        p.content_hash,
        secret.secret,
        secret.line,
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
        fp.target_name,
        fp.share_name,
        p.name || '\\' || fp.path AS path
    FROM
        FullPath AS fp
    JOIN
        path AS p ON p.id = fp.parent_id
)
-- Final selection from the recursive CTE
SELECT DISTINCT
    secret, line, target_name, share_name, path
FROM
    FullPath
"""
