// Copyright (c) Viable Systems
// SPDX-License-Identifier: Apache-2.0

use graphql_client::GraphQLQuery;

pub(crate) type Json = serde_json::Value;
pub(crate) type UInt16 = String;
pub(crate) type CurrencyAmount = String;
pub(crate) type Fee = String;
pub(crate) type PrivateKey = String;
pub(crate) type PublicKey = String;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "graphql/schema.graphql",
    query_path = "graphql/internal_logs_query.graphql",
    response_derives = "Debug",
    variables_derives = "Debug"
)]
pub struct InternalLogsQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "graphql/schema.graphql",
    query_path = "graphql/flush_internal_logs_mutation.graphql",
    response_derives = "Debug",
    variables_derives = "Debug"
)]
pub struct FlushInternalLogsQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "graphql/schema.graphql",
    query_path = "graphql/auth_query.graphql",
    response_derives = "Debug",
    variables_derives = "Debug"
)]
pub struct AuthQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "graphql/schema.graphql",
    query_path = "graphql/reset_zkapp_soft_limit.graphql",
    response_derives = "Debug",
    variables_derives = "Debug"
)]
pub struct ResetZkappSoftLimitQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "graphql/schema.graphql",
    query_path = "graphql/schedule_zkapp_commands.graphql",
    response_derives = "Debug",
    variables_derives = "Debug"
)]
pub struct ScheduleZkappCommandsQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "graphql/schema.graphql",
    query_path = "graphql/schedule_payments.graphql",
    response_derives = "Debug",
    variables_derives = "Debug"
)]
pub struct SchedulePaymentsQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "graphql/schema.graphql",
    query_path = "graphql/stop_payments.graphql",
    response_derives = "Debug",
    variables_derives = "Debug"
)]
pub struct StopPaymentsQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "graphql/schema.graphql",
    query_path = "graphql/update_gating.graphql",
    response_derives = "Debug",
    variables_derives = "Debug"
)]
pub struct UpdateGatingQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "graphql/schema.graphql",
    query_path = "graphql/slots_won_query.graphql",
    response_derives = "Debug",
    variables_derives = "Debug"
)]
pub struct SlotsWonQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "graphql/schema.graphql",
    query_path = "graphql/stop_daemon.graphql",
    response_derives = "Debug",
    variables_derives = "Debug"
)]
pub struct StopDaemonQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "graphql/schema.graphql",
    query_path = "graphql/connection_gating_config.graphql",
    response_derives = "Debug",
    variables_derives = "Debug"
)]
pub struct ConnectionGatingConfigQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "graphql/schema.graphql",
    query_path = "graphql/get_peers.graphql",
    response_derives = "Debug",
    variables_derives = "Debug"
)]
pub struct GetPeersQuery;
