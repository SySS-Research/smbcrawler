config = {
  locateFile: filename => "crawl.sqlite"
}

initSqlJs(config).then(SQL => {
  //Create the database
  const db = new SQL.Database();
  // Run a query without reading the results
  db.run("CREATE TABLE test (col1, col2);");
});
