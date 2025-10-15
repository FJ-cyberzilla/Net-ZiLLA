// internal/storage/database.go
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"net-zilla/internal/models"
	_ "github.com/mattn/go-sqlite3" // or your preferred driver
)

type Database struct {
	db *sql.DB
}

type AnalysisStore interface {
	SaveAnalysis(ctx context.Context, analysis *models.ThreatAnalysis) error
	GetAnalysis(ctx context.Context, id string) (*models.ThreatAnalysis, error)
	GetAnalysisHistory(ctx context.Context, limit int) ([]*models.ThreatAnalysis, error)
	SaveReport(ctx context.Context, report *models.Report) error
}

func NewDatabase(dataSource string) (*Database, error) {
	db, err := sql.Open("sqlite3", dataSource)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Initialize schema
	if err := initSchema(db); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return &Database{db: db}, nil
}

func initSchema(db *sql.DB) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS analyses (
			id TEXT PRIMARY KEY,
			url TEXT NOT NULL,
			threat_level TEXT NOT NULL,
			threat_score INTEGER NOT NULL,
			analysis_data TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		
		`CREATE TABLE IF NOT EXISTS reports (
			id TEXT PRIMARY KEY,
			analysis_id TEXT NOT NULL,
			report_data TEXT NOT NULL,
			format TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (analysis_id) REFERENCES analyses (id)
		)`,
		
		`CREATE TABLE IF NOT EXISTS threat_intel (
			indicator TEXT PRIMARY KEY,
			indicator_type TEXT NOT NULL,
			threat_score INTEGER NOT NULL,
			first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		
		`CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_threat_intel_indicator ON threat_intel(indicator)`,
	}

	for _, query := range queries {
		if _, err := db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query: %w", err)
		}
	}

	return nil
}

func (d *Database) SaveAnalysis(ctx context.Context, analysis *models.ThreatAnalysis) error {
	query := `INSERT INTO analyses (id, url, threat_level, threat_score, analysis_data) 
	          VALUES (?, ?, ?, ?, ?)`
	
	// Convert analysis to JSON for storage
	analysisData, err := json.Marshal(analysis)
	if err != nil {
		return fmt.Errorf("failed to marshal analysis: %w", err)
	}

	_, err = d.db.ExecContext(ctx, query, 
		analysis.AnalysisID, 
		analysis.URL, 
		string(analysis.ThreatLevel),
		analysis.ThreatScore,
		string(analysisData),
	)

	return err
}

func (d *Database) Close() error {
	return d.db.Close()
}
