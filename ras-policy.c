/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Copyright (C) 2026 RAS Daemon Decision Agent
 * 
 * DRAM failure mode detection and analysis using SQLite database
 * Detects CW, Row, Column, and SWD failures
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>

/**
 * parse_iso8601_to_seconds - Convert ISO 8601 timestamp to seconds since epoch
 * 
 * Simplified parser for timestamps in format: "YYYY-MM-DD HH:MM:SS"
 * Returns seconds since epoch for comparison
 * 
 * @timestamp: ISO 8601 timestamp string
 * Returns: Seconds since epoch (approximation), or -1 on parse error
 */
static time_t parse_iso8601_to_seconds(const char *timestamp)
{
	int year, month, day, hour, minute, second;
	int days_in_months[] = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};
	
	if (sscanf(timestamp, "%d-%d-%d %d:%d:%d",
		   &year, &month, &day, &hour, &minute, &second) != 6)
		return -1;
	
	if (month < 1 || month > 12 || day < 1 || day > 31)
		return -1;
	
	/* Rough calculation: days since epoch + seconds in day */
	int days_since_1970 = (year - 1970) * 365 + days_in_months[month] + day - 1;
	/* Add leap days (simplified) */
	days_since_1970 += (year - 1969) / 4 - (year - 1901) / 100 + (year - 1601) / 400;
	
	return days_since_1970 * 86400 + hour * 3600 + minute * 60 + second;
}

/**
 * is_within_time_window - Check if two timestamps are within 1 hour
 * 
 * @ts1: First timestamp (ISO 8601 format)
 * @ts2: Second timestamp (ISO 8601 format)
 * Returns: 1 if within 1 hour, 0 otherwise
 */
static int is_within_time_window(const char *ts1, const char *ts2)
{
	time_t time1 = parse_iso8601_to_seconds(ts1);
	time_t time2 = parse_iso8601_to_seconds(ts2);
	
	if (time1 == -1 || time2 == -1)
		return 0;
	
	time_t diff = (time1 > time2) ? (time1 - time2) : (time2 - time1);
	return diff <= 3600;  /* 3600 seconds = 1 hour */
}


/**
 * struct error_record - Single error record from database
 * @channel:   DRAM channel
 * @rank:      DRAM rank
 * @bank:      DRAM bank
 * @row:       DRAM row
 * @col:       DRAM column
 * @timestamp: ISO 8601 timestamp string
 * @severity:  "UE" for Uncorrected Error, "CE" for Corrected Error
 */
struct error_record {
	int32_t channel;
	int32_t rank;
	int32_t bank;
	int32_t row;
	int32_t col;
	char timestamp[32];
	char severity[8];
};

/**
 * check_cw_failure - Detect  Codeword / Single Page failures
 * 
 * Rule: >= 2 errors on the exact same (Channel, Rank, Bank, Row, Col)
 *       AND all errors within 1 hour time window
 * 
 * @db: SQLite database connection
 * Returns: Number of CW failures detected
 */
static int check_cw_failure(sqlite3 *db)
{
	sqlite3_stmt *stmt;
	int count = 0;
	const char *query = 
		"SELECT dram_channel, dram_rank, dram_bank, dram_row, dram_col, "
		"       MIN(timestamp) as min_ts, MAX(timestamp) as max_ts, COUNT(*) as error_count "
		"FROM mce_record "
		"WHERE dram_channel IS NOT NULL AND dram_rank IS NOT NULL "
		"  AND dram_bank IS NOT NULL AND dram_row IS NOT NULL "
		"  AND dram_col IS NOT NULL "
		"GROUP BY dram_channel, dram_rank, dram_bank, dram_row, dram_col "
		"HAVING COUNT(*) >= 2";

	int rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Failed to prepare CW query: %s\n",
			sqlite3_errmsg(db));
		return -1;
	}

	printf("\n=== Check 1: CW (Codeword/Page) Failure ===\n");
	printf("Detecting: >= 2 errors at identical (Channel, Rank, Bank, Row, Col) within 1 hour\n");

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		int32_t channel = sqlite3_column_int(stmt, 0);
		int32_t rank = sqlite3_column_int(stmt, 1);
		int32_t bank = sqlite3_column_int(stmt, 2);
		int32_t row = sqlite3_column_int(stmt, 3);
		int32_t col = sqlite3_column_int(stmt, 4);
		const char *min_ts = (const char *)sqlite3_column_text(stmt, 5);
		const char *max_ts = (const char *)sqlite3_column_text(stmt, 6);
		int error_count = sqlite3_column_int(stmt, 7);

		/* Check if all errors are within 1 hour window */
		if (!is_within_time_window(min_ts, max_ts))
			continue;

		printf("  DETECTED: %d errors at Ch%d Rk%d Bk%d Row%d Col%d\n",
		       error_count, channel, rank, bank, row, col);
		printf("  ACTION: Offline Page [Addr: Ch%d Rk%d Bk%d Row%d Col%d]\n",
		       channel, rank, bank, row, col);
		count++;
	}

	sqlite3_finalize(stmt);
	
	if (count == 0)
		printf("  Result: No CW failures detected\n");
	
	return count;
}

/**
 * check_row_failure - Detect Row failures
 * 
 * Rule: >= 2 errors on same (Channel, Rank, Bank, Row) but different Columns
 *       AND all errors within 1 hour time window
 * 
 * @db: SQLite database connection
 * Returns: Number of Row failures detected
 */
static int check_row_failure(sqlite3 *db)
{
	sqlite3_stmt *stmt;
	int count = 0;
	const char *query = 
		"SELECT dram_channel, dram_rank, dram_bank, dram_row, "
		"       COUNT(DISTINCT dram_col) as col_count, "
		"       MIN(timestamp) as min_ts, MAX(timestamp) as max_ts "
		"FROM mce_record "
		"WHERE dram_channel IS NOT NULL AND dram_rank IS NOT NULL "
		"  AND dram_bank IS NOT NULL AND dram_row IS NOT NULL "
		"GROUP BY dram_channel, dram_rank, dram_bank, dram_row "
		"HAVING COUNT(DISTINCT dram_col) >= 2";

	int rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Failed to prepare Row query: %s\n",
			sqlite3_errmsg(db));
		return -1;
	}

	printf("\n=== Check 2: Row Failure ===\n");
	printf("Detecting: >= 2 errors in same (Channel, Rank, Bank, Row) but different Columns within 1 hour\n");

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		int32_t channel = sqlite3_column_int(stmt, 0);
		int32_t rank = sqlite3_column_int(stmt, 1);
		int32_t bank = sqlite3_column_int(stmt, 2);
		int32_t row = sqlite3_column_int(stmt, 3);
		int col_count = sqlite3_column_int(stmt, 4);
		const char *min_ts = (const char *)sqlite3_column_text(stmt, 5);
		const char *max_ts = (const char *)sqlite3_column_text(stmt, 6);

		/* Check if all errors are within 1 hour window */
		if (!is_within_time_window(min_ts, max_ts))
			continue;

		printf("  DETECTED: %d different columns in Ch%d Rk%d Bk%d Row%d\n",
		       col_count, channel, rank, bank, row);
		printf("  ACTION: Offline Row [Addr: Ch%d Rk%d Bk%d Row%d]\n",
		       channel, rank, bank, row);
		count++;
	}

	sqlite3_finalize(stmt);
	
	if (count == 0)
		printf("  Result: No Row failures detected\n");
	
	return count;
}

/**
 * check_column_failure - Detect Column failures
 * 
 * Rule: >= 2 errors on same (Channel, Rank, Bank, Col) but different Rows
 *       AND all errors within 1 hour time window
 * 
 * @db: SQLite database connection
 * Returns: Number of Column failures detected
 */
static int check_column_failure(sqlite3 *db)
{
	sqlite3_stmt *stmt;
	int count = 0;
	const char *query = 
		"SELECT dram_channel, dram_rank, dram_bank, dram_col, "
		"       COUNT(DISTINCT dram_row) as row_count, "
		"       MIN(timestamp) as min_ts, MAX(timestamp) as max_ts "
		"FROM mce_record "
		"WHERE dram_channel IS NOT NULL AND dram_rank IS NOT NULL "
		"  AND dram_bank IS NOT NULL AND dram_col IS NOT NULL "
		"GROUP BY dram_channel, dram_rank, dram_bank, dram_col "
		"HAVING COUNT(DISTINCT dram_row) >= 2";

	int rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Failed to prepare Column query: %s\n",
			sqlite3_errmsg(db));
		return -1;
	}

	printf("\n=== Check 3: Column Failure ===\n");
	printf("Detecting: >= 2 errors in same (Channel, Rank, Bank, Col) but different Rows within 1 hour\n");

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		int32_t channel = sqlite3_column_int(stmt, 0);
		int32_t rank = sqlite3_column_int(stmt, 1);
		int32_t bank = sqlite3_column_int(stmt, 2);
		int32_t col = sqlite3_column_int(stmt, 3);
		int row_count = sqlite3_column_int(stmt, 4);
		const char *min_ts = (const char *)sqlite3_column_text(stmt, 5);
		const char *max_ts = (const char *)sqlite3_column_text(stmt, 6);

		/* Check if all errors are within 1 hour window */
		if (!is_within_time_window(min_ts, max_ts))
			continue;

		printf("  DETECTED: %d different rows in Ch%d Rk%d Bk%d Col%d\n",
		       row_count, channel, rank, bank, col);
		printf("  ACTION: Offline Column (+/- 1024 Rows) [Addr: Ch%d Rk%d Bk%d Col%d]\n",
		       channel, rank, bank, col);
		count++;
	}

	sqlite3_finalize(stmt);
	
	if (count == 0)
		printf("  Result: No Column failures detected\n");
	
	return count;
}

/**
 * check_swd_failure - Detect SWD (Spatial/Sparse Word Disturb) failures
 * 
 * Rule: >= 3 errors across 2+ DISTINCT rows where (Row_Max - Row_Min) <= 8 
 *       for same Channel/Rank/Bank AND all errors within 1 hour time window
 * 
 * Key differentiator: Requires 2+ distinct rows (not 3+ errors in same row)
 * - Single row with 3+ errors = Row Failure
 * - Multiple rows (2+) with 3+ total errors in 8-row window = SWD Failure
 * 
 * Implementation: Fetch all records with timestamps, sorted by Channel, Rank, Bank, Row.
 * Use a sliding window to find regions with 3+ errors across multiple rows in 8-row window.
 * 
 * @db: SQLite database connection
 * Returns: Number of SWD failures detected
 */
static int check_swd_failure(sqlite3 *db)
{
	sqlite3_stmt *stmt;
	struct error_record *records = NULL;
	int record_count = 0;
	int record_capacity = 256;
	int detected_count = 0;
	const char *query = 
		"SELECT dram_channel, dram_rank, dram_bank, dram_row, timestamp "
		"FROM mce_record "
		"WHERE dram_channel IS NOT NULL AND dram_rank IS NOT NULL "
		"  AND dram_bank IS NOT NULL AND dram_row IS NOT NULL "
		"ORDER BY dram_channel, dram_rank, dram_bank, dram_row";

	printf("\n=== Check 4: SWD Failure ===\n");
	printf("Detecting: >= 3 errors where (Row_Max - Row_Min) <= 8 per Channel/Rank/Bank within 1 hour\n");

	/* Allocate initial buffer for records */
	records = malloc(record_capacity * sizeof(struct error_record));
	if (!records) {
		fprintf(stderr, "Failed to allocate memory for records\n");
		return -1;
	}

	/* Fetch all error locations with timestamps */
	int rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Failed to prepare SWD query: %s\n",
			sqlite3_errmsg(db));
		free(records);
		return -1;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		/* Expand buffer if needed */
		if (record_count >= record_capacity) {
			record_capacity *= 2;
			struct error_record *tmp = realloc(records,
				record_capacity * sizeof(struct error_record));
			if (!tmp) {
				fprintf(stderr, "Failed to reallocate memory\n");
				sqlite3_finalize(stmt);
				free(records);
				return -1;
			}
			records = tmp;
		}

		records[record_count].channel = sqlite3_column_int(stmt, 0);
		records[record_count].rank = sqlite3_column_int(stmt, 1);
		records[record_count].bank = sqlite3_column_int(stmt, 2);
		records[record_count].row = sqlite3_column_int(stmt, 3);
		const char *ts = (const char *)sqlite3_column_text(stmt, 4);
		strncpy(records[record_count].timestamp, ts ? ts : "", sizeof(records[record_count].timestamp) - 1);
		records[record_count].timestamp[sizeof(records[record_count].timestamp) - 1] = '\0';
		record_count++;
	}

	sqlite3_finalize(stmt);

	/* Analyze records for SWD patterns using sliding window */
	for (int i = 0; i < record_count; i++) {
		int32_t ch = records[i].channel;
		int32_t rk = records[i].rank;
		int32_t bk = records[i].bank;
		int32_t min_row = records[i].row;
		int32_t max_row = min_row;
		int window_count = 1;
		const char *first_ts = records[i].timestamp;
		const char *last_ts = first_ts;

		/*
		 * Build a window: collect consecutive records with same
		 * channel/rank/bank and find all those within an 8-row range
		 */
		for (int j = i + 1; j < record_count; j++) {
			if (records[j].channel != ch ||
			    records[j].rank != rk ||
			    records[j].bank != bk)
				break;

			int32_t row = records[j].row;
			int32_t potential_max = (row > max_row) ? row : max_row;
			
			/* Check if this record fits within the 8-row window */
			if (potential_max - min_row <= 8) {
				window_count++;
				max_row = potential_max;
				last_ts = records[j].timestamp;
			}
		}

		/* 
		 * SWD requires:
		 * - 3+ errors
		 * - Across 2+ DISTINCT rows (max_row > min_row ensures this)
		 * - Row range <= 8
		 * - Within 1 hour time window
		 * This differentiates SWD from single-row failures
		 */
		if (window_count >= 3 && max_row > min_row && is_within_time_window(first_ts, last_ts)) {
			int32_t center_row = (min_row + max_row) / 2;
			printf("  DETECTED: %d errors in Ch%d Rk%d Bk%d "
			       "Row range [%d-%d]\n",
			       window_count, ch, rk, bk, min_row, max_row);
			printf("  ACTION: Offline Region (+/- 8 Rows) "
			       "[Addr: Ch%d Rk%d Bk%d CenterRow%d]\n",
			       ch, rk, bk, center_row);
			detected_count++;
		}
	}

	free(records);

	if (detected_count == 0)
		printf("  Result: No SWD failures detected\n");
	
	return detected_count;
}

/**
 * check_single_ue_failure - Detect Single Uncorrected Error (UE) failures
 * 
 * Rule: Any UE (Uncorrected Error) on ANY DRAM address is classified as CW UE
 * Note: UE failures are reported regardless of time window due to criticality
 * 
 * @db: SQLite database connection
 * Returns: Number of UE failures detected
 */
static int check_single_ue_failure(sqlite3 *db)
{
	sqlite3_stmt *stmt;
	int count = 0;
	const char *query = 
		"SELECT dram_channel, dram_rank, dram_bank, dram_row, dram_col, severity, timestamp "
		"FROM mce_record "
		"WHERE dram_channel IS NOT NULL AND dram_rank IS NOT NULL "
		"  AND dram_bank IS NOT NULL AND severity = 'UE'";

	int rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Failed to prepare UE query: %s\n",
			sqlite3_errmsg(db));
		return -1;
	}

	printf("\n=== Check 5: Single UE (Uncorrected Error) Failure ===\n");
	printf("Detecting: Any UE on ANY DRAM address (reported regardless of time due to criticality)\n");

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		int32_t channel = sqlite3_column_int(stmt, 0);
		int32_t rank = sqlite3_column_int(stmt, 1);
		int32_t bank = sqlite3_column_int(stmt, 2);
		int32_t row = sqlite3_column_int(stmt, 3);
		int32_t col = sqlite3_column_int(stmt, 4);
		const char *severity = (const char *)sqlite3_column_text(stmt, 5);
		const char *timestamp = (const char *)sqlite3_column_text(stmt, 6);

		printf("  DETECTED: UE at Ch%d Rk%d Bk%d Row%d Col%d (Severity: %s, Time: %s)\n",
		       channel, rank, bank, row, col, severity, timestamp ? timestamp : "unknown");
		printf("  ACTION: Offline Page [Addr: Ch%d Rk%d Bk%d Row%d Col%d] - CRITICAL\n",
		       channel, rank, bank, row, col);
		count++;
	}

	sqlite3_finalize(stmt);
	
	if (count == 0)
		printf("  Result: No UE failures detected\n");
	
	return count;
}

/**
 * analyze_failure_modes - Main analysis function
 * 
 * Connects to SQLite database and runs all 4 failure mode detection checks
 * 
 * @db_path: Path to RAS daemon SQLite database
 * Returns: 0 on success, -1 on failure
 */
int analyze_failure_modes(const char *db_path)
{
	sqlite3 *db;
	int rc, cw_count, row_count, col_count, swd_count, ue_count;

	printf("Opening RAS daemon database: %s\n", db_path);
	rc = sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Failed to open database: %s\n",
			sqlite3_errmsg(db));
		if (db)
			sqlite3_close(db);
		return -1;
	}

	printf("Database opened successfully\n");

	/* Run all five failure mode checks */
	cw_count = check_cw_failure(db);
	row_count = check_row_failure(db);
	col_count = check_column_failure(db);
	swd_count = check_swd_failure(db);
	ue_count = check_single_ue_failure(db);

	/* Summary report */
	printf("\n" "================================================\n");
	printf("FAILURE MODE ANALYSIS SUMMARY\n");
	printf("================================================\n");
	printf("CW (Codeword/Page) Failures:     %d\n", cw_count);
	printf("Row Failures:                         %d\n", row_count);
	printf("Column Failures:                      %d\n", col_count);
	printf("SWD Failures:                         %d\n", swd_count);
	printf("UE (Single Uncorrected Error):        %d\n", ue_count);
	printf("================================================\n");
	printf("Total Failure Modes Detected:         %d\n",
	       cw_count + row_count + col_count + swd_count + ue_count);
	printf("================================================\n");

	sqlite3_close(db);
	return 0;
}

/**
 * main - Entry point for decision agent
 * 
 * Usage: ras-policy [db_path]
 *   db_path: Optional path to RAS database (default: /var/lib/rasdaemon/ras-mc_event.db)
 */
int main(int argc, char *argv[])
{
	const char *db_path = "/var/lib/rasdaemon/ras-mc_event.db";

	/* Allow override of database path via command-line argument */
	if (argc > 1)
		db_path = argv[1];

	printf("=== RAS Daemon Decision Agent - Failure Mode Analyzer ===\n");
	printf("\n");

	if (analyze_failure_modes(db_path) != 0)
		return 1;

	return 0;
}
