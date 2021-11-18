/*
Copyright 2021 The Vitess Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package singleton

import (
	"flag"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"vitess.io/vitess/go/mysql"
	"vitess.io/vitess/go/vt/schema"

	"vitess.io/vitess/go/test/endtoend/cluster"
	"vitess.io/vitess/go/test/endtoend/onlineddl"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	clusterInstance *cluster.LocalProcessCluster
	shards          []cluster.Shard
	vtParams        mysql.ConnParams

	hostname              = "localhost"
	keyspaceName          = "ks"
	cell                  = "zone1"
	schemaChangeDirectory = ""
	tableName             = `onlineddl_test`
	createTableWrapper    = `CREATE TABLE onlineddl_test(%s)`
	dropTableStatement    = `
		DROP TABLE IF EXISTS onlineddl_test
	`
	ddlStrategy = "online -declarative -allow-zero-in-date"
)

type testCase struct {
	name       string
	fromSchema string
	toSchema   string
	// expectProblems              bool
	removedUniqueKeyNames       string
	droppedNoDefaultColumnNames string
	expandedColumnNames         string
}

var testCases = []testCase{
	{
		name:       "identical schemas",
		fromSchema: `id int primary key, i1 int not null default 0`,
		toSchema:   `id int primary key, i2 int not null default 0`,
	},
	{
		name:       "different schemas, nothing to note",
		fromSchema: `id int primary key, i1 int not null default 0, unique key i1_uidx(i1)`,
		toSchema:   `id int primary key, i1 int not null default 0, i2 int not null default 0, unique key i1_uidx(i1)`,
	},
	{
		name:                  "removed non-nullable unique key",
		fromSchema:            `id int primary key, i1 int not null default 0, unique key i1_uidx(i1)`,
		toSchema:              `id int primary key, i2 int not null default 0`,
		removedUniqueKeyNames: `i1_uidx`,
	},
	{
		name:                  "removed nullable unique key",
		fromSchema:            `id int primary key, i1 int default null, unique key i1_uidx(i1)`,
		toSchema:              `id int primary key, i2 int default null`,
		removedUniqueKeyNames: `i1_uidx`,
	},
	{
		name:                  "expanding unique key removes unique constraint",
		fromSchema:            `id int primary key, i1 int default null, unique key i1_uidx(i1)`,
		toSchema:              `id int primary key, i1 int default null, unique key i1_uidx(i1, id)`,
		removedUniqueKeyNames: `i1_uidx`,
	},
	{
		name:                  "reducing unique key does not unique constraint",
		fromSchema:            `id int primary key, i1 int default null, unique key i1_uidx(i1, id)`,
		toSchema:              `id int primary key, i1 int default null, unique key i1_uidx(i1)`,
		removedUniqueKeyNames: ``,
	},
	{
		name:                        "remove column without default",
		fromSchema:                  `id int primary key, i1 int not null`,
		toSchema:                    `id int primary key, i2 int not null default 0`,
		droppedNoDefaultColumnNames: `i1`,
	},
}

func TestMain(m *testing.M) {
	defer cluster.PanicHandler(nil)
	flag.Parse()

	exitcode, err := func() (int, error) {
		clusterInstance = cluster.NewCluster(cell, hostname)
		schemaChangeDirectory = path.Join("/tmp", fmt.Sprintf("schema_change_dir_%d", clusterInstance.GetAndReserveTabletUID()))
		defer os.RemoveAll(schemaChangeDirectory)
		defer clusterInstance.Teardown()

		if _, err := os.Stat(schemaChangeDirectory); os.IsNotExist(err) {
			_ = os.Mkdir(schemaChangeDirectory, 0700)
		}

		clusterInstance.VtctldExtraArgs = []string{
			"-schema_change_dir", schemaChangeDirectory,
			"-schema_change_controller", "local",
			"-schema_change_check_interval", "1"}

		clusterInstance.VtTabletExtraArgs = []string{
			"-enable-lag-throttler",
			"-throttle_threshold", "1s",
			"-heartbeat_enable",
			"-heartbeat_interval", "250ms",
		}
		clusterInstance.VtGateExtraArgs = []string{}

		if err := clusterInstance.StartTopo(); err != nil {
			return 1, err
		}

		// Start keyspace
		keyspace := &cluster.Keyspace{
			Name: keyspaceName,
		}

		// No need for replicas in this stress test
		if err := clusterInstance.StartKeyspace(*keyspace, []string{"1"}, 0, false); err != nil {
			return 1, err
		}

		vtgateInstance := clusterInstance.NewVtgateInstance()
		// set the gateway we want to use
		vtgateInstance.GatewayImplementation = "tabletgateway"
		// Start vtgate
		if err := vtgateInstance.Setup(); err != nil {
			return 1, err
		}
		// ensure it is torn down during cluster TearDown
		clusterInstance.VtgateProcess = *vtgateInstance
		vtParams = mysql.ConnParams{
			Host: clusterInstance.Hostname,
			Port: clusterInstance.VtgateMySQLPort,
		}

		return m.Run(), nil
	}()
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	} else {
		os.Exit(exitcode)
	}

}

func TestSchemaChange(t *testing.T) {
	defer cluster.PanicHandler(t)
	shards = clusterInstance.Keyspaces[0].Shards
	require.Equal(t, 1, len(shards))

	for _, testcase := range testCases {
		t.Run(testcase.name, func(t *testing.T) {

			t.Run("ensure table dropped", func(t *testing.T) {
				uuid := testOnlineDDLStatement(t, dropTableStatement, ddlStrategy, "vtgate", "", "", false)
				onlineddl.CheckMigrationStatus(t, &vtParams, shards, uuid, schema.OnlineDDLStatusComplete)
				checkTable(t, tableName, false)
			})

			t.Run("create from-table", func(t *testing.T) {
				fromStatement := fmt.Sprintf(createTableWrapper, testcase.fromSchema)
				uuid := testOnlineDDLStatement(t, fromStatement, ddlStrategy, "vtgate", "", "", false)
				onlineddl.CheckMigrationStatus(t, &vtParams, shards, uuid, schema.OnlineDDLStatusComplete)
				checkTable(t, tableName, true)
			})
			var uuid string
			t.Run("run migration", func(t *testing.T) {
				toStatement := fmt.Sprintf(createTableWrapper, testcase.toSchema)
				uuid = testOnlineDDLStatement(t, toStatement, ddlStrategy, "vtgate", "", "", false)
				onlineddl.CheckMigrationStatus(t, &vtParams, shards, uuid, schema.OnlineDDLStatusComplete)
				checkTable(t, tableName, true)
			})
			t.Run("check migration", func(t *testing.T) {
				rs := onlineddl.ReadMigrations(t, &vtParams, uuid)
				require.NotNil(t, rs)
				for _, row := range rs.Named().Rows {
					removedUniqueKeyNames := row.AsString("removed_unique_key_names", "")
					droppedNoDefaultColumnNames := row.AsString("dropped_no_default_column_names", "")
					expandedColumnNames := row.AsString("expanded_column_names", "")

					assert.Equal(t, removedUniqueKeyNames, testcase.removedUniqueKeyNames)
					assert.Equal(t, droppedNoDefaultColumnNames, testcase.droppedNoDefaultColumnNames)
					assert.Equal(t, expandedColumnNames, testcase.expandedColumnNames)
				}
			})
		})
	}
}

// testOnlineDDLStatement runs an online DDL, ALTER statement
func testOnlineDDLStatement(t *testing.T, alterStatement string, ddlStrategy string, executeStrategy string, expectHint string, expectError string, skipWait bool) (uuid string) {
	strategySetting, err := schema.ParseDDLStrategy(ddlStrategy)
	require.NoError(t, err)

	if executeStrategy == "vtgate" {
		result := onlineddl.VtgateExecDDL(t, &vtParams, ddlStrategy, alterStatement, expectError)
		if result != nil {
			row := result.Named().Row()
			if row != nil {
				uuid = row.AsString("uuid", "")
			}
		}
	} else {
		output, err := clusterInstance.VtctlclientProcess.ApplySchemaWithOutput(keyspaceName, alterStatement, cluster.VtctlClientParams{DDLStrategy: ddlStrategy, SkipPreflight: true})
		if expectError == "" {
			assert.NoError(t, err)
			uuid = output
		} else {
			assert.Error(t, err)
			assert.Contains(t, output, expectError)
		}
	}
	uuid = strings.TrimSpace(uuid)
	fmt.Println("# Generated UUID (for debug purposes):")
	fmt.Printf("<%s>\n", uuid)

	if !strategySetting.Strategy.IsDirect() && !skipWait {
		status := onlineddl.WaitForMigrationStatus(t, &vtParams, shards, uuid, 20*time.Second, schema.OnlineDDLStatusComplete, schema.OnlineDDLStatusFailed)
		fmt.Printf("# Migration status (for debug purposes): <%s>\n", status)
	}

	if expectError == "" && expectHint != "" {
		checkMigratedTable(t, tableName, expectHint)
	}
	return uuid
}

// checkTable checks the number of tables in the first two shards.
func checkTable(t *testing.T, showTableName string, expectExists bool) bool {
	expectCount := 0
	if expectExists {
		expectCount = 1
	}
	for i := range clusterInstance.Keyspaces[0].Shards {
		if !checkTablesCount(t, clusterInstance.Keyspaces[0].Shards[i].Vttablets[0], showTableName, expectCount) {
			return false
		}
	}
	return true
}

// checkTablesCount checks the number of tables in the given tablet
func checkTablesCount(t *testing.T, tablet *cluster.Vttablet, showTableName string, expectCount int) bool {
	query := fmt.Sprintf(`show tables like '%%%s%%';`, showTableName)
	queryResult, err := tablet.VttabletProcess.QueryTablet(query, keyspaceName, true)
	require.Nil(t, err)
	return assert.Equal(t, expectCount, len(queryResult.Rows))
}

// checkMigratedTables checks the CREATE STATEMENT of a table after migration
func checkMigratedTable(t *testing.T, tableName, expectHint string) {
	for i := range clusterInstance.Keyspaces[0].Shards {
		createStatement := getCreateTableStatement(t, clusterInstance.Keyspaces[0].Shards[i].Vttablets[0], tableName)
		assert.Contains(t, createStatement, expectHint)
	}
}

// getCreateTableStatement returns the CREATE TABLE statement for a given table
func getCreateTableStatement(t *testing.T, tablet *cluster.Vttablet, tableName string) (statement string) {
	queryResult, err := tablet.VttabletProcess.QueryTablet(fmt.Sprintf("show create table %s;", tableName), keyspaceName, true)
	require.Nil(t, err)

	assert.Equal(t, len(queryResult.Rows), 1)
	assert.Equal(t, len(queryResult.Rows[0]), 2) // table name, create statement
	statement = queryResult.Rows[0][1].ToString()
	return statement
}
