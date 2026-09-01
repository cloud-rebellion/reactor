package journal

// Engine reports the journal's configured SQL dialect. Execution frontends
// use it to choose topology, not to assemble SQL: PostgreSQL is the distributed
// deployment and must enqueue work for leased workers, while SQLite supports
// the explicit single-process development path.
func (j *Journal) Engine() Engine { return j.engine }
