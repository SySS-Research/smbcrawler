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
ORDER BY
    target_name, share_name, path
""",
    high_value_shares=(
        "SELECT name, 'target' AS target_id FROM Share WHERE high_value = True"
    ),
    secrets_unique="""
    SELECT DISTINCT
        secret
    FROM
        secret
    ORDER BY
        secret
    """,
    secrets_with_paths="""
WITH

    -- First: formulate recursive CTE to construct the full path.
    -- This CTE contains the reflexive-transitive closure of the parent-relationship.
    -- I.e. for an example full path dir1/dir2/file.txt,
    -- it contains rows for file.txt, dir2/file.txt, and dir1/dir2/file.txt.
    RECURSIVE FullPath__ AS (
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
            p.name AS path,
            -- Propagate the original id (primary key) of the secret;
            -- it is used later for grouping.
            p.id as orig_id
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
            p.name || '\\' || fp.path AS path,
            fp.orig_id as orig_id
        FROM
            FullPath__ AS fp
        JOIN
            path AS p ON p.id = fp.parent_id
    ),

    -- Second: group/partition the previous CTE by file/secret and
    -- inside each of those order the entries by length descending.
    -- => the first entry by rowid in each partition is the full path (the longest).
    FullPath_ AS (
        SELECT *, ROW_NUMBER() OVER (PARTITION BY orig_id ORDER BY length(path) DESC) AS rn
        FROM FullPath__
    ),

    -- Third: For all parent-paths originating from a specific file/secret,
    -- now only select the longest one; this is the full path.
    -- Thereby, intermediate paths are removed from the query result.
    FullPath AS (
        SELECT *
        FROM FullPath_
        WHERE rn = 1
    )

-- Final selection from the recursive CTE
SELECT
    secret, line, line_number, target_name, share_name, path, content_hash
FROM
    FullPath
ORDER BY
    secret, target_name, share_name, path
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
ORDER BY
    target_name, share_name, full_path
""",
    shares_listable_root="SELECT * FROM share WHERE read_level > 0 ORDER BY target_id, name",
    shares_listable_root_as_guest='SELECT * FROM share WHERE read_level > 0 AND guest_access = "1" ORDER BY target_id, name',
    shares_writable='SELECT * FROM share WHERE write_access = "1" ORDER BY target_id, name',
    summary="""
SELECT 'number_targets' AS key, count(*) AS value FROM target
UNION ALL
SELECT 'number_targets_with_open_ports' AS key, count(*) AS value FROM target WHERE port_open = "1"
UNION ALL
SELECT 'number_targets_with_open_shares' AS key, count(DISTINCT target_id) AS value FROM share
UNION ALL
SELECT 'number_shares' AS key, count(*) AS value FROM share
UNION ALL
SELECT 'number_shares_listable_root' AS key, count(*) AS value FROM shares_listable_root
UNION ALL
SELECT 'number_shares_listable_root_as_guest' AS key, count(*) AS value FROM shares_listable_root_as_guest
UNION ALL
SELECT 'number_shares_writable' AS key, count(*) AS value FROM shares_writable
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
