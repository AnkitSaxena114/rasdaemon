/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Copyright (C) 2026 RAS Daemon Test Harness
 * 
 * Test harness to inject mock MCE records into SQLite database
 * for simulating different DRAM failure modes
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <time.h>

#include "config.h"

#define DB_PATH RASSTATEDIR "/" RAS_DB_FNAME

/**
 * inject_record - Insert a single MCE record into mce_record table
 * 
 * @db:           SQLite database connection
 * @timestamp:    Timestamp string (ISO format)
 * @channel:      DRAM channel
 * @rank:         DRAM rank
 * @bank:         DRAM bank
 * @row:          DRAM row (use -1 for no row)
 * @col:          DRAM column (use -1 for no column)
 * @severity:     "UE" for Uncorrected Error, "CE" for Corrected Error
 * 
 * Returns 0 on success, -1 on failure
 */
static int inject_record(sqlite3 *db, const char *timestamp,
			 int32_t channel, int32_t rank, int32_t bank,
			 int32_t row, int32_t col, const char *severity)
{
	sqlite3_stmt *stmt;
	const char *insert_sql = 
		"INSERT INTO mce_record ("
		"timestamp, mcgcap, mcgstatus, status, addr, misc, ip, tsc, "
		"walltime, ppin, cpu, cpuid, apicid, socketid, cs, bank, cpuvendor, "
		"microcode, bank_name, error_msg, mcgstatus_msg, mcistatus_msg, "
		"mcastatus_msg, user_action, mc_location, "
		"dram_channel, dram_rank, dram_bank, dram_row, dram_col, severity) "
		"VALUES (?, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "
		"'test_bank', 'mock_error', '', '', '', '', '', ?, ?, ?, ?, ?, ?)";

	int rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Failed to prepare statement: %s\n",
			sqlite3_errmsg(db));
		return -1;
	}

	/* Bind timestamp (parameter 1) */
	rc = sqlite3_bind_text(stmt, 1, timestamp, -1, NULL);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Failed to bind timestamp: %s\n",
			sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return -1;
	}

	/* Bind DRAM fields (parameters 26-30 in full table, but 2-6 in INSERT) */
	sqlite3_bind_int(stmt, 2, channel);
	sqlite3_bind_int(stmt, 3, rank);
	sqlite3_bind_int(stmt, 4, bank);
	sqlite3_bind_int(stmt, 5, row);
	sqlite3_bind_int(stmt, 6, col);
	/* Bind severity field (parameter 7) */
	sqlite3_bind_text(stmt, 7, severity, -1, NULL);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		fprintf(stderr, "Failed to execute insert: %s\n",
			sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return -1;
	}

	sqlite3_finalize(stmt);
	return 0;
}

/**
 * get_timestamp_string - Generate an ISO 8601 timestamp with optional offset
 * 
 * @buf:      Buffer to store timestamp
 * @buf_size: Size of buffer
 * @offset:   Seconds to add to current time (for creating distinct timestamps)
 */
static void get_timestamp_string(char *buf, size_t buf_size, int offset)
{
	time_t now = time(NULL) + offset;
	struct tm *tm_info = gmtime(&now);
	strftime(buf, buf_size, "%Y-%m-%d %H:%M:%S", tm_info);
}

int main(int argc, char *argv[])
{
	sqlite3 *db;
	int rc;
	char timestamp[32];
	const char *db_path = DB_PATH;

	/* Allow override of database path via command-line argument */
	if (argc > 1)
		db_path = argv[1];

	printf("Opening RAS daemon database: %s\n", db_path);
	rc = sqlite3_open(db_path, &db);
	if (rc) {
		fprintf(stderr, "Failed to open database: %s\n",
			sqlite3_errmsg(db));
		sqlite3_close(db);
		return 1;
	}

	printf("Database opened successfully\n");

	/*
	 * SCENARIO 1: CW / Single Page Failure
	 * Two errors at the same physical address (identical channel, rank, bank, row, col)
	 * This indicates a critical word or single page failure
	 */
	printf("\n=== Scenario 1: CW / Single Page Failure ===\n");
	get_timestamp_string(timestamp, sizeof(timestamp), 0);
	printf("Injecting record 1 (Channel=1, Rank=0, Bank=2, Row=100, Col=50) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 1, 0, 2, 100, 50, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 1, record 1\n");
		goto fail;
	}

	get_timestamp_string(timestamp, sizeof(timestamp), 60);
	printf("Injecting record 2 (Channel=1, Rank=0, Bank=2, Row=100, Col=50) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 1, 0, 2, 100, 50, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 1, record 2\n");
		goto fail;
	}
	printf("✓ Scenario 1 injection complete\n");

	/*
	 * SCENARIO 2: Row Failure
	 * Two errors in the same row but different columns
	 * Indicates the entire row is failing
	 */
	printf("\n=== Scenario 2: Row Failure ===\n");
	get_timestamp_string(timestamp, sizeof(timestamp), 120);
	printf("Injecting record 1 (Channel=1, Rank=0, Bank=2, Row=200, Col=10) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 1, 0, 2, 200, 10, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 2, record 1\n");
		goto fail;
	}

	get_timestamp_string(timestamp, sizeof(timestamp), 180);
	printf("Injecting record 2 (Channel=1, Rank=0, Bank=2, Row=200, Col=20) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 1, 0, 2, 200, 20, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 2, record 2\n");
		goto fail;
	}
	printf("✓ Scenario 2 injection complete\n");

	/*
	 * SCENARIO 3: Column Failure
	 * Two errors in the same column but different rows
	 * Indicates the entire column is failing
	 */
	printf("\n=== Scenario 3: Column Failure ===\n");
	get_timestamp_string(timestamp, sizeof(timestamp), 240);
	printf("Injecting record 1 (Channel=1, Rank=0, Bank=2, Row=1000, Col=300) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 1, 0, 2, 1000, 300, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 3, record 1\n");
		goto fail;
	}

	get_timestamp_string(timestamp, sizeof(timestamp), 300);
	printf("Injecting record 2 (Channel=1, Rank=0, Bank=2, Row=2000, Col=300) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 1, 0, 2, 2000, 300, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 3, record 2\n");
		goto fail;
	}
	printf("✓ Scenario 3 injection complete\n");

	/*
	 * SCENARIO 4: SWD (Sub-Wordline-Driver) Failure
	 * Three errors in the same rank/bank/channel but within adjacent rows (range <= 8)
	 * Indicates systematic defect across multiple word lines
	 */
	printf("\n=== Scenario 4: SWD (Sub-Wordline-Driver) Failure ===\n");
	get_timestamp_string(timestamp, sizeof(timestamp), 360);
	printf("Injecting record 1 (Channel=1, Rank=0, Bank=2, Row=500) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 1, 0, 2, 500, 100, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 4, record 1\n");
		goto fail;
	}

	get_timestamp_string(timestamp, sizeof(timestamp), 420);
	printf("Injecting record 2 (Channel=1, Rank=0, Bank=2, Row=502) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 1, 0, 2, 502, 150, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 4, record 2\n");
		goto fail;
	}

	get_timestamp_string(timestamp, sizeof(timestamp), 480);
	printf("Injecting record 3 (Channel=1, Rank=0, Bank=2, Row=505) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 1, 0, 2, 505, 200, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 4, record 3\n");
		goto fail;
	}
	printf("✓ Scenario 4 injection complete\n");

	/*
	 * SCENARIO 5: Single UE (Uncorrected Error) Failure
	 * Any UE error on any DRAM address (regardless of pattern)
	 * Indicates a critical hardware fault requiring immediate attention
	 */
	printf("\n=== Scenario 5: Single UE (Uncorrected Error) Failure ===\n");
	get_timestamp_string(timestamp, sizeof(timestamp), 540);
	printf("Injecting record 1 (Channel=0, Rank=1, Bank=3, Row=50, Col=75) - UE at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 0, 1, 3, 50, 75, "UE") != 0) {
		fprintf(stderr, "Failed to inject scenario 5, record 1\n");
		goto fail;
	}

	get_timestamp_string(timestamp, sizeof(timestamp), 600);
	printf("Injecting record 2 (Channel=2, Rank=0, Bank=1, Row=1500, Col=200) - UE at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 2, 0, 1, 1500, 200, "UE") != 0) {
		fprintf(stderr, "Failed to inject scenario 5, record 2\n");
		goto fail;
	}
	printf("✓ Scenario 5 injection complete\n");

	printf("\n" "================================================\n");
	printf("✓ All test scenarios injected successfully!\n");
	printf("  - Scenario 1: CW/Single Page (2 records)\n");
	printf("  - Scenario 2: Row Failure (2 records)\n");
	printf("  - Scenario 3: Column Failure (2 records)\n");
	printf("  - Scenario 4: SWD Failure (3 records)\n");
	printf("  - Scenario 5: Single UE Failure (2 UE records)\n");

	/*
	 * SCENARIO 6: Scattered Errors (No Failure Pattern)
	 * Multiple errors across different channels/ranks/banks with no coherent pattern
	 * These should NOT trigger any failure mode detection
	 */
	printf("\n=== Scenario 6: Scattered Errors (No Failure Pattern) ===\n");
	get_timestamp_string(timestamp, sizeof(timestamp), 660);
	printf("Injecting record 1 (Channel=0, Rank=0, Bank=0, Row=10, Col=5) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 0, 0, 0, 10, 5, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 6, record 1\n");
		goto fail;
	}

	get_timestamp_string(timestamp, sizeof(timestamp), 720);
	printf("Injecting record 2 (Channel=2, Rank=1, Bank=3, Row=300, Col=150) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 2, 1, 3, 300, 150, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 6, record 2\n");
		goto fail;
	}

	get_timestamp_string(timestamp, sizeof(timestamp), 780);
	printf("Injecting record 3 (Channel=1, Rank=2, Bank=1, Row=500, Col=50) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 1, 2, 1, 500, 50, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 6, record 3\n");
		goto fail;
	}
	printf("✓ Scenario 6 injection complete\n");

	/*
	 * SCENARIO 7: Extended Row Failure
	 * Multiple errors (4+) in the same row but different columns
	 * Shows scalability: can detect many columns failing in one row
	 */
	printf("\n=== Scenario 7: Extended Row Failure (4 columns) ===\n");
	get_timestamp_string(timestamp, sizeof(timestamp), 840);
	printf("Injecting record 1 (Channel=3, Rank=1, Bank=0, Row=2000, Col=10) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 3, 1, 0, 2000, 10, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 7, record 1\n");
		goto fail;
	}

	get_timestamp_string(timestamp, sizeof(timestamp), 900);
	printf("Injecting record 2 (Channel=3, Rank=1, Bank=0, Row=2000, Col=50) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 3, 1, 0, 2000, 50, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 7, record 2\n");
		goto fail;
	}

	get_timestamp_string(timestamp, sizeof(timestamp), 960);
	printf("Injecting record 3 (Channel=3, Rank=1, Bank=0, Row=2000, Col=100) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 3, 1, 0, 2000, 100, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 7, record 3\n");
		goto fail;
	}

	get_timestamp_string(timestamp, sizeof(timestamp), 1020);
	printf("Injecting record 4 (Channel=3, Rank=1, Bank=0, Row=2000, Col=200) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 3, 1, 0, 2000, 200, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 7, record 4\n");
		goto fail;
	}
	printf("✓ Scenario 7 injection complete\n");

	/*
	 * SCENARIO 8: Extended Column Failure
	 * Multiple errors (4+) in the same column but different rows
	 * Shows scalability: can detect many rows failing in one column
	 */
	printf("\n=== Scenario 8: Extended Column Failure (4 rows) ===\n");
	get_timestamp_string(timestamp, sizeof(timestamp), 1080);
	printf("Injecting record 1 (Channel=0, Rank=2, Bank=2, Row=3000, Col=400) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 0, 2, 2, 3000, 400, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 8, record 1\n");
		goto fail;
	}

	get_timestamp_string(timestamp, sizeof(timestamp), 1140);
	printf("Injecting record 2 (Channel=0, Rank=2, Bank=2, Row=3500, Col=400) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 0, 2, 2, 3500, 400, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 8, record 2\n");
		goto fail;
	}

	get_timestamp_string(timestamp, sizeof(timestamp), 1200);
	printf("Injecting record 3 (Channel=0, Rank=2, Bank=2, Row=4000, Col=400) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 0, 2, 2, 4000, 400, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 8, record 3\n");
		goto fail;
	}

	get_timestamp_string(timestamp, sizeof(timestamp), 1260);
	printf("Injecting record 4 (Channel=0, Rank=2, Bank=2, Row=4500, Col=400) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 0, 2, 2, 4500, 400, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 8, record 4\n");
		goto fail;
	}
	printf("✓ Scenario 8 injection complete\n");

	/*
	 * SCENARIO 9: Out-of-Window Errors (Time Boundary Test)
	 * Two errors at same location but > 1 hour apart
	 * Should NOT be classified as CW failure due to time window constraint
	 */
	printf("\n=== Scenario 9: Out-of-Window Errors (1+ hours apart) ===\n");
	get_timestamp_string(timestamp, sizeof(timestamp), 1320);
	printf("Injecting record 1 (Channel=1, Rank=3, Bank=2, Row=5000, Col=250) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 1, 3, 2, 5000, 250, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 9, record 1\n");
		goto fail;
	}

	/* 2 hours later (7200 seconds) */
	get_timestamp_string(timestamp, sizeof(timestamp), 1320 + 7200);
	printf("Injecting record 2 (Channel=1, Rank=3, Bank=2, Row=5000, Col=250) at %s\n",
	       timestamp);
	printf("  (Note: This is 2 hours after record 1, exceeds 1-hour window)\n");
	if (inject_record(db, timestamp, 1, 3, 2, 5000, 250, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 9, record 2\n");
		goto fail;
	}
	printf("✓ Scenario 9 injection complete\n");

	/*
	 * SCENARIO 10: Multiple Row Failures
	 * Two DIFFERENT rows in same channel/rank/bank, each with multiple columns failing
	 * Validates system can detect and report 2+ independent row failures
	 * Row1: Columns [10, 20]
	 * Row2: Columns [30, 40]
	 */
	printf("\n=== Scenario 10: Multiple Row Failures (2 rows) ===\n");
	get_timestamp_string(timestamp, sizeof(timestamp), 1500);
	printf("Injecting record 1 (Channel=2, Rank=0, Bank=3, Row=6000, Col=10) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 2, 0, 3, 6000, 10, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 10, record 1\n");
		goto fail;
	}

	get_timestamp_string(timestamp, sizeof(timestamp), 1560);
	printf("Injecting record 2 (Channel=2, Rank=0, Bank=3, Row=6000, Col=20) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 2, 0, 3, 6000, 20, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 10, record 2\n");
		goto fail;
	}

	get_timestamp_string(timestamp, sizeof(timestamp), 1620);
	printf("Injecting record 3 (Channel=2, Rank=0, Bank=3, Row=6050, Col=30) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 2, 0, 3, 6050, 30, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 10, record 3\n");
		goto fail;
	}

	get_timestamp_string(timestamp, sizeof(timestamp), 1680);
	printf("Injecting record 4 (Channel=2, Rank=0, Bank=3, Row=6050, Col=40) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 2, 0, 3, 6050, 40, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 10, record 4\n");
		goto fail;
	}
	printf("✓ Scenario 10 injection complete\n");

	/*
	 * SCENARIO 11: Multiple Column Failures
	 * Two DIFFERENT columns in same channel/rank/bank, each with multiple rows failing
	 * Validates system can detect and report 2+ independent column failures
	 * Col1: Rows [7000, 7500]
	 * Col2: Rows [8000, 8500]
	 */
	printf("\n=== Scenario 11: Multiple Column Failures (2 columns) ===\n");
	get_timestamp_string(timestamp, sizeof(timestamp), 1740);
	printf("Injecting record 1 (Channel=3, Rank=2, Bank=1, Row=7000, Col=500) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 3, 2, 1, 7000, 500, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 11, record 1\n");
		goto fail;
	}

	get_timestamp_string(timestamp, sizeof(timestamp), 1800);
	printf("Injecting record 2 (Channel=3, Rank=2, Bank=1, Row=7500, Col=500) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 3, 2, 1, 7500, 500, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 11, record 2\n");
		goto fail;
	}

	get_timestamp_string(timestamp, sizeof(timestamp), 1860);
	printf("Injecting record 3 (Channel=3, Rank=2, Bank=1, Row=8000, Col=600) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 3, 2, 1, 8000, 600, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 11, record 3\n");
		goto fail;
	}

	get_timestamp_string(timestamp, sizeof(timestamp), 1920);
	printf("Injecting record 4 (Channel=3, Rank=2, Bank=1, Row=8500, Col=600) at %s\n",
	       timestamp);
	if (inject_record(db, timestamp, 3, 2, 1, 8500, 600, "CE") != 0) {
		fprintf(stderr, "Failed to inject scenario 11, record 4\n");
		goto fail;
	}
	printf("✓ Scenario 11 injection complete\n");

	printf("\n" "================================================\n");
	printf("✓ All test scenarios injected successfully!\n");
	printf("  - Scenario 1: CW/Single Page (2 records, same address)\n");
	printf("  - Scenario 2: Row Failure (2 records, same row, diff cols)\n");
	printf("  - Scenario 3: Column Failure (2 records, same col, diff rows)\n");
	printf("  - Scenario 4: SWD Failure (3 records, 8-row window)\n");
	printf("  - Scenario 5: Single UE Failure (2 UE records)\n");
	printf("  - Scenario 6: Scattered Errors (3 records, no pattern)\n");
	printf("  - Scenario 7: Extended Row Failure (4 columns in 1 row)\n");
	printf("  - Scenario 8: Extended Column Failure (4 rows in 1 col)\n");
	printf("  - Scenario 9: Out-of-Window Errors (2 records > 1 hour apart)\n");
	printf("  - Scenario 10: Multiple Row Failures (2 rows, 2 cols each)\n");
	printf("  - Scenario 11: Multiple Column Failures (2 cols, 2 rows each)\n");
	printf("  Total: 32 mock MCE records in database\n");
	printf("================================================\n");

	sqlite3_close(db);
	return 0;

fail:
	sqlite3_close(db);
	return 1;
}
