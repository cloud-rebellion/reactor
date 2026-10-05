package journal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
)

const (
	CommandDiagnosticRunError  = "run_error"
	CommandDiagnosticStdout    = "stdout"
	CommandDiagnosticStderr    = "stderr"
	CommandDiagnosticStepError = "step_error"

	// A page is deliberately much smaller than the journal's capture limit.
	MaxCommandDiagnosticPageBytes   = 16 << 10
	MaxCommandDiagnosticOffsetBytes = 16 << 20
)

var ErrInvalidCommandDiagnosticPage = errors.New("journal: invalid command diagnostic page")

type CommandRunDiagnosticPage struct {
	Content    []byte
	TotalBytes int
}

// ReadCommandRunDiagnosticPageForTenant returns a byte-exact page of the
// persisted diagnostic. Step sources use the durable attempt row rather than
// the mutable current-step projection, so a retry cannot silently substitute
// another attempt. The tenant, run, step, and attempt predicates are checked
// in the same SQL read. Authorization and audit-before-return belong to the
// caller; this method must not be used for an ordinary AI-facing read.
func (j *Journal) ReadCommandRunDiagnosticPageForTenant(ctx context.Context, tenantID, runID, source string, stepSeq, attempt, offsetBytes, limitBytes int) (CommandRunDiagnosticPage, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(runID) == "" {
		return CommandRunDiagnosticPage{}, ErrNotFound
	}
	if offsetBytes < 0 || offsetBytes > MaxCommandDiagnosticOffsetBytes || limitBytes < 1 || limitBytes > MaxCommandDiagnosticPageBytes {
		return CommandRunDiagnosticPage{}, ErrInvalidCommandDiagnosticPage
	}
	var column, versionColumn, from, predicate, field string
	var args []any
	switch source {
	case CommandDiagnosticRunError:
		if stepSeq != 0 || attempt != 0 {
			return CommandRunDiagnosticPage{}, ErrInvalidCommandDiagnosticPage
		}
		column, versionColumn, from, field = "r.error_text", "r.error_crypto_version", "command_runs r", "run_error"
		predicate = "r.tenant_id = $1 AND r.id = $2"
		args = []any{tenantID, runID}
	case CommandDiagnosticStdout, CommandDiagnosticStderr, CommandDiagnosticStepError:
		if stepSeq < 1 || attempt < 1 {
			return CommandRunDiagnosticPage{}, ErrInvalidCommandDiagnosticPage
		}
		switch source {
		case CommandDiagnosticStdout:
			column = "a.stdout_text"
			versionColumn, field = "a.stdout_crypto_version", "attempt_stdout"
		case CommandDiagnosticStderr:
			column = "a.stderr_text"
			versionColumn, field = "a.stderr_crypto_version", "attempt_stderr"
		case CommandDiagnosticStepError:
			column = "a.error_text"
			versionColumn, field = "a.error_crypto_version", "attempt_error"
		}
		from = "command_run_step_attempts a JOIN command_runs r ON r.id = a.run_id"
		predicate = "r.tenant_id = $1 AND a.run_id = $2 AND a.step_seq = $3 AND a.attempt = $4"
		args = []any{tenantID, runID, stepSeq, attempt}
	default:
		return CommandRunDiagnosticPage{}, ErrInvalidCommandDiagnosticPage
	}

	var bytesExpr, pageExpr string
	if j.engine == EnginePostgres {
		bytesExpr = "convert_to(" + column + ", 'UTF8')"
		pageExpr = fmt.Sprintf("substring(%s from %d for %d)", bytesExpr, offsetBytes+1, limitBytes)
	} else {
		bytesExpr = "CAST(" + column + " AS BLOB)"
		pageExpr = fmt.Sprintf("substr(%s, %d, %d)", bytesExpr, offsetBytes+1, limitBytes)
	}
	sizeExpr := j.commandTextSize(column)
	// Legacy rows are sliced by SQL before materialization. A version-one
	// envelope is bounded by SQL, authenticated in Go, and then byte-sliced.
	query := fmt.Sprintf(`SELECT CASE WHEN %s = 0 THEN %s
		WHEN %s = 1 AND %s <= %d THEN %s ELSE NULL END, %s,
		CASE WHEN %s = 0 THEN COALESCE(%s, 0) ELSE 0 END
		FROM %s WHERE %s`, versionColumn, pageExpr, versionColumn,
		sizeExpr, payloadcrypto.CiphertextLimit(commandFieldLimit(field)), bytesExpr,
		versionColumn, versionColumn, sizeExpr, from, predicate)
	var page CommandRunDiagnosticPage
	var stored []byte
	var version int
	if err := j.db.QueryRowContext(ctx, j.bind(query), args...).Scan(&stored, &version, &page.TotalBytes); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CommandRunDiagnosticPage{}, ErrNotFound
		}
		return CommandRunDiagnosticPage{}, fmt.Errorf("journal: read command diagnostic page: %w", err)
	}
	if version == 1 {
		plain, err := j.openCommandField(tenantID, runID, stepSeq, attempt, field, version, sql.NullString{String: string(stored), Valid: stored != nil})
		if err != nil {
			return CommandRunDiagnosticPage{}, err
		}
		page.TotalBytes = len(plain)
		if offsetBytes >= len(plain) {
			page.Content = []byte{}
			return page, nil
		}
		end := offsetBytes + limitBytes
		if end > len(plain) {
			end = len(plain)
		}
		page.Content = []byte(plain[offsetBytes:end])
	} else if version == 0 {
		page.Content = stored
	} else {
		return CommandRunDiagnosticPage{}, payloadcrypto.ErrInvalidEnvelope
	}
	return page, nil
}
