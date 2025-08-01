open Core
open Async

type checkpoint_entry =
  [ `Checkpoint of string * float | `Control of string * Yojson.Safe.t ]

type full_checkpoint =
  { source : [ `Main | `Verifier | `Prover ]
  ; call_id : int
  ; checkpoint : checkpoint_entry
  }

module Pending = struct
  let parent_and_finish_checkpoints = function
    | "Verifier_verify_transaction_snarks" ->
        Some
          ( "Verify_transaction_snarks"
          , "Verifier_verify_transaction_snarks_done" )
    | "Verifier_verify_blockchain_snarks" ->
        Some
          ("Verify_blockchain_snarks", "Verifier_verify_blockchain_snarks_done")
    | "Verifier_verify_commands" ->
        Some ("Verify_commands", "Verifier_verify_commands_done")
    | "Prover_extend_blockchain" ->
        Some ("Produce_state_transition_proof", "Prover_extend_blockchain_done")
    | _ ->
        None
end

(* TODO: this implementation is not complete *)
let push_kimchi_checkpoints_from_metadata _trace parent_entry
    (metadata : Yojson.Safe.t) =
  try
    let checkpoints =
      let open Yojson.Safe.Util in
      metadata |> member "traces" |> to_string |> String.split_lines
      |> List.map ~f:Yojson.Safe.from_string
    in
    let checkpoints =
      List.map checkpoints ~f:(fun json ->
          match json with
          | `List [ `String checkpoint; `Float timestamp ] ->
              `Checkpoint (checkpoint, timestamp)
          | `Assoc metadata ->
              `Metadata metadata
          | _ ->
              failwith "got malformed kimchi checkpoints" )
    in
    let current_entry = ref parent_entry in
    List.iter checkpoints ~f:(function
      | `Checkpoint (checkpoint, _timestamp) ->
          let _checkpoint = "Kimchi_" ^ checkpoint in
          let _prev_checkpoint = !current_entry.Block_trace.Entry.checkpoint in
          (* TODO: handle kimchi entries recording here *)
          (*current_entry :=
            Block_tracing.record ~block_id ~checkpoint ~timestamp
              ~target_trace:`Main ~order:(`Chronological_after prev_checkpoint)
              ()*)
          ()
      | `Metadata metadata ->
          !current_entry.metadata <- `Assoc metadata )
  with exn ->
    Log.Global.error "[WARN] failed to integrate kimchi checkpoints: %s"
      (Exn.to_string exn) ;
    Log.Global.error "BACKTRACE:\n%s" (Printexc.get_backtrace ())

module Persisted_block_trace = struct
  open Block_trace

  type t =
    { source : block_source
    ; deployment_id : int
    ; blockchain_length : int
    ; global_slot : int
    ; status : status
    ; started_at : float
    ; total_time : float
    ; metadata : Yojson.Safe.t
    }
  [@@deriving to_yojson]

  let from_block_trace
      ( { Block_trace.source
        ; deployment_id
        ; blockchain_length
        ; global_slot
        ; status
        ; total_time
        ; metadata
        ; checkpoints = _
        ; other_checkpoints = _
        } as t ) =
    { source
    ; deployment_id
    ; blockchain_length 
    ; global_slot
    ; status
    ; started_at = started_at t
    ; total_time
    ; metadata
    }

  let add_pending_entries_to_block_trace ~parent_checkpoint ~default_deployment_id pending_entries
      (trace : Block_trace.t) =
    (* these must be processed at the end *)
    let pending_kimchi_entries = ref [] in
    let rec loop ~previous_checkpoint entries
        (current_entry : Block_trace.Entry.t) (trace : Block_trace.t) =
      match entries with
      | `Checkpoint (checkpoint, timestamp) :: entries ->
          let current_entry = Entry.make ~timestamp checkpoint in
          let trace =
            Block_trace.push ~status:trace.status ~source:trace.source
              ~target_trace:`Main
              ~order:(`Chronological_after previous_checkpoint) 
              ~default_deployment_id current_entry (Some trace)
          in
          loop ~previous_checkpoint:checkpoint entries current_entry trace
      | `Control ("metadata", data) :: entries ->
          (* for these entries the metadata will become checkpoints *)
          if
            String.equal "Backend_tick_proof_create_async"
              current_entry.checkpoint
            || String.equal "Backend_tock_proof_create_async"
                 current_entry.checkpoint
          then
            pending_kimchi_entries :=
              (current_entry, data) :: !pending_kimchi_entries
          else
            current_entry.metadata <-
              Yojson.Safe.Util.combine current_entry.metadata data ;
          loop ~previous_checkpoint entries current_entry trace
      | `Control (_, _) :: entries ->
          (* printf "Ignoring control %s\n%!" other ; *)
          loop ~previous_checkpoint entries current_entry trace
      | [] ->
          List.iter !pending_kimchi_entries ~f:(fun (parent_entry, data) ->
              push_kimchi_checkpoints_from_metadata trace parent_entry data ) ;
          trace
    in
    loop ~previous_checkpoint:parent_checkpoint pending_entries
      (Block_trace.Entry.make ~timestamp:0.0 "")
      trace

  let integrate_extra_checkpoints trace ~default_deployment_id ~(checkpoints : checkpoint_entry list) =
    let first_checkpoint =
      match checkpoints with
      | `Checkpoint (name, _) :: _ ->
          name
      | _ ->
          raise Exit
    in
    let last_pending_entry = List.last checkpoints in
    match
      ( Pending.parent_and_finish_checkpoints first_checkpoint
      , last_pending_entry )
    with
    | ( Some (parent_checkpoint, end_checkpoint)
      , Some (`Checkpoint (last_checkpoint, _)) )
      when String.equal end_checkpoint last_checkpoint ->
        add_pending_entries_to_block_trace ~parent_checkpoint ~default_deployment_id checkpoints trace
    | _ ->
        trace

  let integrate_extra_checkpoints trace ~checkpoints ~default_deployment_id =
    try integrate_extra_checkpoints trace ~checkpoints ~default_deployment_id with Exit -> trace

  let to_block_trace ?(checkpoints = []) ~default_deployment_id
      { source
      ; deployment_id
      ; blockchain_length
      ; global_slot
      ; status
      ; started_at = _
      ; total_time
      ; metadata
      } =
    let trace =
      { Block_trace.source
      ; deployment_id
      ; blockchain_length
      ; global_slot
      ; status = `Pending
      ; total_time
      ; metadata
      ; checkpoints = []
      ; other_checkpoints = []
      }
    in
    let main_checkpoints =
      List.filter_map checkpoints ~f:(function
        | { source = `Main; call_id = _; checkpoint } ->
            Some checkpoint
        | _ ->
            None )
    in
    let prover_checkpoints =
      List.fold checkpoints ~init:Int.Map.empty ~f:(fun acc entry ->
          match entry with
          | { source = `Prover; call_id; checkpoint } ->
              Int.Map.update acc call_id ~f:(fun cps ->
                  checkpoint :: Option.value cps ~default:[] )
          | _ ->
              acc )
    in
    let verifier_checkpoints =
      List.fold checkpoints ~init:Int.Map.empty ~f:(fun acc entry ->
          match entry with
          | { source = `Verifier; call_id; checkpoint } ->
              Int.Map.update acc call_id ~f:(fun cps ->
                  checkpoint :: Option.value cps ~default:[] )
          | _ ->
              acc )
    in
    let trace =
      List.fold main_checkpoints ~init:trace ~f:(fun trace checkpoint ->
          match checkpoint with
          | `Checkpoint (name, timestamp) ->
              let entry = Block_trace.Entry.make ~timestamp name in
              Block_trace.push
                ~status:(Block_tracing.compute_status name)
                ~source ~order:`Append 
                ~default_deployment_id
                ~target_trace:`Main entry (Some trace)
          | `Control ("metadata", metadata) ->
              let metadata = Yojson.Safe.Util.to_assoc metadata in
              Block_trace.push_metadata ~metadata (Some trace)
              |> Option.value_exn
          | _ ->
              trace )
    in
    let trace =
      Int.Map.fold ~init:trace
        ~f:(fun ~key:_ ~data:checkpoints_rev trace ->
          integrate_extra_checkpoints trace
            ~checkpoints:(List.rev checkpoints_rev)
            ~default_deployment_id )
        prover_checkpoints
    in
    let trace =
      Int.Map.fold ~init:trace
        ~f:(fun ~key:_ ~data:checkpoints_rev trace ->
          integrate_extra_checkpoints trace
            ~checkpoints:(List.rev checkpoints_rev)
            ~default_deployment_id
         )
        verifier_checkpoints
    in
    (*if not @@ List.is_empty prover_checkpoints then
          List.fold prover_checkpoints ~init:trace ~f:(fun trace _checkpoint ->
              trace )
        else trace
      in*)
    (*let trace =
        if not @@ List.is_empty verifier_checkpoints then
          List.fold verifier_checkpoints ~init:trace ~f:(fun trace _checkpoint ->
              trace )
        else trace
      in*)
    { trace with status }

  let to_block_trace_info
      ( state_hash
      , { source
        ; deployment_id
        ; blockchain_length
        ; global_slot
        ; status
        ; started_at
        ; total_time
        ; metadata
        } ) =
    Block_tracing.Registry.
      { state_hash
      ; source
      ; deployment_id
      ; blockchain_length
      ; global_slot
      ; status
      ; started_at
      ; total_time
      ; metadata
      }

  let block_source_to_string = block_source_to_string

  let block_source_from_string = block_source_from_string

  let status_to_string = status_to_string

  let status_from_string = status_from_string
end

module Q = struct
  open Caqti_request.Infix
  open Caqti_type.Std
  
  (* Use tup functions with deprecation warnings suppressed *)
  [@@@warning "-3"]
  let t2 = tup2
  let t3 = tup3  
  let t4 = tup4
  [@@@warning "+3"]

  let block_id = Caqti_type.string

  let block_trace_id = Caqti_type.int

  let block_trace =
    let open Persisted_block_trace in
    let encode
        { source
        ; blockchain_length
        ; global_slot
        ; status
        ; started_at
        ; total_time
        ; metadata
        ; deployment_id
        } =
      let source = block_source_to_string source in
      let status = status_to_string status in
      let completed_at = started_at +. total_time in
      let metadata_json = Yojson.Safe.to_string metadata in
      Ok
        ( (started_at, completed_at, total_time)
        , (source, blockchain_length, global_slot, status)
        , (metadata_json, deployment_id)  )
    in
    let decode
        ( (started_at, _trace_completed_at, total_time)
        , (source, blockchain_length, global_slot, status)
        , (metadata_json, deployment_id) ) =
      let status = status_from_string status in
      let metadata = Yojson.Safe.from_string metadata_json in
      let source = block_source_from_string source in
      Ok
        { source
        ; deployment_id
        ; blockchain_length
        ; global_slot
        ; status
        ; started_at
        ; total_time
        ; metadata
        }
    in
    let rep =
      Caqti_type.(
        t3 (t3 float float float ) (t4 string int int string)  (t2 string int) )
    in
    custom ~encode ~decode rep

  let block_trace_with_id = t2 block_trace_id block_trace

  let block_trace_with_block_id = t2 block_id block_trace

  let block_trace_info =
    let open Block_tracing.Registry in
    let encode _ = assert false in
    let decode
        ( block_id
        , (source, blockchain_length, global_slot, status)
        , (started_at, total_time)
        , (metadata_json, deployment_id) ) =
      let status = Block_trace.status_from_string status in
      let metadata = Yojson.Safe.from_string metadata_json in
      let source = Block_trace.block_source_from_string source in
      Ok
        { source
        ; blockchain_length
        ; global_slot
        ; state_hash = block_id
        ; status
        ; started_at
        ; total_time
        ; deployment_id
        ; metadata
        }
    in
    let rep =
      Caqti_type.(
        t4 string (t4 string int int string) (t2 float float) (t2 string int) )
    in
    custom ~encode ~decode rep

  let block_trace_checkpoint =
    let encode { source; call_id; checkpoint } =
      let source =
        match source with `Main -> "M" | `Verifier -> "V" | `Prover -> "P"
      in
      let is_control, name, timestamp, metadata =
        match checkpoint with
        | `Checkpoint (name, timestamp) ->
            (false, name, timestamp, "[]")
        | `Control (name, metadata) ->
            (true, name, -1.0, Yojson.Safe.to_string metadata)
      in
      Ok (source, call_id, (is_control, name, timestamp, metadata))
    in
    let decode (source, call_id, (is_control, name, timestamp, metadata)) =
      let source =
        match source with
        | "M" ->
            `Main
        | "V" ->
            `Verifier
        | "P" ->
            `Prover
        | _ ->
            `Main
        (* TODO print warning *)
      in
      (* TODO: print warning on metadata decoding failure or fail row decoding *)
      let checkpoint =
        if is_control then
          `Control
            (name, try Yojson.Safe.from_string metadata with _exn -> `Assoc [])
        else `Checkpoint (name, timestamp)
      in
      Ok { source; call_id; checkpoint }
    in
    let rep = Caqti_type.(t3 string int (t4 bool string float string)) in
    custom ~encode ~decode rep

  let block_trace_checkpoint_with_trace_id =
    Caqti_type.(t3 block_trace_id bool block_trace_checkpoint)

  
  let add_block_trace =
    (t2 string block_trace_with_block_id ->! int)
         {eos|
        INSERT INTO block_trace (
          node_name, block_id, 
          trace_started_at, trace_completed_at, total_time,
          source, blockchain_length, global_slot, status,
          metadata_json, deployment_id
        )
        VALUES (?,?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING block_trace_id
      |eos}
        

  let update_block_trace =
    (t2 block_trace block_trace_id ->. unit)
      {eos|
        UPDATE block_trace SET
          trace_started_at = ?,
          trace_completed_at = ?,
          total_time = ?,
          source = ?,
          blockchain_length = ?,
          global_slot = ?,
          status = ?,
          metadata_json = ?,
          deployment_id = ?
        WHERE block_trace_id = ?
      |eos}

  let update_block_trace_block_id =
    (t2 block_id block_trace_id ->. unit)
      {eos|
        UPDATE block_trace SET block_id = ? 
        WHERE 
          block_trace_id = ? 
          and deployment_id = get_max_deployment_id()
      |eos}

  let select_block_traces =
    (t3 block_id string int ->* block_trace_with_id)
      {eos|
        SELECT
          block_trace_id,
          trace_started_at, trace_completed_at, total_time,
          source, blockchain_length, global_slot, status,
          CAST(metadata_json AS text) metadata_json, deployment_id
        FROM block_trace
        WHERE block_id = ?
          AND node_name = ?
          AND deployment_id = ?
        ORDER BY block_trace_id DESC
        LIMIT 1
      |eos}
    
  let select_block_trace =
    (block_trace_id ->! block_trace_with_block_id)
      {eos|
        SELECT
          block_id,
          trace_started_at, trace_completed_at, total_time,
          source, blockchain_length, global_slot, status,
          CAST(metadata_json AS text) metadata_json, deployment_id
        FROM block_trace
        WHERE block_trace_id = ?
      |eos}

  let base_block_traces_query =
    (* TODO use window function instead of INNER JOIN *)
    {eos|
      SELECT
          bt.block_id,
          bt.source, bt.blockchain_length, bt.global_slot, bt.status,
          bt.trace_started_at, bt.total_time,
          CAST(bt.metadata_json AS text) metadata_json, bt.deployment_id
      FROM block_trace bt
      WHERE bt.node_name = $1
    |eos}

  let select_block_trace_info_entries_asc =
    (t3 string (t2 int int) int ->* block_trace_info)
    @@ base_block_traces_query
    ^ {eos|
      AND bt.deployment_id = $4
      ORDER BY bt.block_trace_id ASC
      LIMIT $2
      OFFSET $3
    |eos}

  let select_block_trace_info_entries_desc =
    (t3 string (t2 int int) int ->* block_trace_info)
    @@ base_block_traces_query 
    ^ {eos|
      AND bt.deployment_id = $4
      ORDER BY bt.block_trace_id DESC
      LIMIT $2
      OFFSET $3
    |eos}

  let select_block_trace_info_entries order =
    match order with
    | `Asc ->
        select_block_trace_info_entries_asc 
    | `Desc ->
        select_block_trace_info_entries_desc 

  let select_block_trace_info_entries_by_global_slot_asc =
    (t3 string (t4 int int int int) int ->* block_trace_info)
    @@ base_block_traces_query
    ^ {eos|
        AND bt.global_slot > $4 AND bt.global_slot <= $5
        AND bt.deployment_id = $6
      ORDER BY bt.block_trace_id ASC
      LIMIT $2
      OFFSET $3
    |eos}

  let select_block_trace_info_entries_by_global_slot_desc =
    (t3 string (t4 int int int int) int ->* block_trace_info)
    @@ base_block_traces_query
    ^ {eos|
        AND bt.global_slot > $4 AND bt.global_slot <= $5
        AND bt.deployment_id = $6
      ORDER BY bt.block_trace_id DESC
      LIMIT $2
      OFFSET $3
    |eos}

  let select_block_trace_info_entries_by_global_slot order =
    match order with
    | `Asc ->
        select_block_trace_info_entries_by_global_slot_asc
    | `Desc ->
        select_block_trace_info_entries_by_global_slot_desc

  let select_block_trace_info_entries_by_height_asc =
    (t3 string (t4 int int int int) int ->* block_trace_info)
    @@ base_block_traces_query
    ^ {eos|
        AND bt.blockchain_length > $4 AND bt.blockchain_length <= $5
        AND bt.deployment_id = $6
      ORDER BY bt.block_trace_id ASC
      LIMIT $2
      OFFSET $3
    |eos}

  let select_block_trace_info_entries_by_height_desc =
    (t3 string (t4 int int int int) int ->* block_trace_info)
    @@ base_block_traces_query
    ^ {eos|
        AND bt.blockchain_length > $4 AND bt.blockchain_length <= $5
        AND bt.deployment_id = $6
      ORDER BY bt.block_trace_id DESC
      LIMIT $2
      OFFSET $3
    |eos}

  let select_block_trace_info_entries_by_height order =
    match order with
    | `Asc ->
        select_block_trace_info_entries_by_height_asc
    | `Desc ->
        select_block_trace_info_entries_by_height_desc

  let add_block_trace_checkpoint =
    (block_trace_checkpoint_with_trace_id ->. unit)
      {eos|
        INSERT INTO block_trace_checkpoint (
          block_trace_id,
          main_trace,
          source,
          call_id,
          is_control,
          name,
          started_at,
          metadata_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      |eos}

  let select_block_trace_checkpoints =
    (t2 int bool ->* block_trace_checkpoint)
      {eos|
        SELECT
          source, call_id, is_control, name, started_at,
          CAST(metadata_json AS text) metadata_json
        FROM block_trace_checkpoint
        WHERE block_trace_id = ? AND main_trace = ? AND NOT gossip
        ORDER BY block_trace_checkpoint_id ASC
      |eos}

  let set_value =
    (t3 string string string ->. unit)
         {eos|
        INSERT INTO data (key, deployment_id, value, node_name) VALUES (?, get_max_deployment_id() , ?, ?)
        ON CONFLICT (key, deployment_id, node_name) DO UPDATE SET value = excluded.value
      |eos}
    

  let get_current_deployment_id =
    (unit ->! int) {eos| SELECT get_max_deployment_id() |eos}

  let get_deployments_ids =
    (unit ->* int) {eos| SELECT deployment_id from deployment |eos}

  let get_value =
    (t3 string string int ->? string)
         {eos| SELECT value FROM data WHERE node_name = ? AND key = ? AND deployment_id = ? |eos}


  let get_nodes_names =
    (int ->* (t2 string int) )
         {eos| SELECT node_name, deployment_id FROM data WHERE deployment_id = ? |eos}
end

let add_block_trace block_id trace node_name (module Db : Caqti_async.CONNECTION) =
  Db.find Q.add_block_trace (node_name, (block_id, trace) )

let add_block_trace block_id trace node_name =
  Connection_context.use_current (add_block_trace block_id trace node_name)

let update_block_trace block_trace_id trace (module Db : Caqti_async.CONNECTION)
    =
  Db.exec Q.update_block_trace (trace, block_trace_id)

let update_block_trace block_trace_id trace =
  Connection_context.use_current (update_block_trace block_trace_id trace)

let get_block_traces block_id deployment_id node_name (module Db : Caqti_async.CONNECTION) =
  Db.collect_list Q.select_block_traces (block_id, node_name, deployment_id)

let get_block_traces block_id deployment_id node_name =
  Connection_context.use_current (get_block_traces block_id node_name deployment_id)

let get_block_trace_by_id block_trace_id (module Db : Caqti_async.CONNECTION) =
  Db.find Q.select_block_trace block_trace_id

let get_block_trace_by_id block_trace_id =
  Connection_context.use_current (get_block_trace_by_id block_trace_id)

let get_block_trace_info_entries ?(max_length = 10_000) ?(offset = 0) ?height
    ?global_slot ?(chain_length = 1) ?(order = `Asc) deployment_id node_name
    (module Db : Caqti_async.CONNECTION) =
  match (global_slot, height) with
  | Some global_slot_end, _ ->
      let global_slot_start = global_slot_end - chain_length in
      Db.collect_list
        (Q.select_block_trace_info_entries_by_global_slot order)
        (node_name, (max_length, offset, global_slot_start, global_slot_end), deployment_id)
  | None, Some height_end ->
      let height_start = height_end - chain_length in
      Db.collect_list
        (Q.select_block_trace_info_entries_by_height order)
        (node_name, (max_length, offset, height_start, height_end), deployment_id)
  | None, None ->
      Db.collect_list
        (Q.select_block_trace_info_entries order)
        (node_name, (max_length, offset), deployment_id)

let get_block_trace_info_entries ?max_length ?offset ?height ?global_slot
    ?chain_length ?order deployment_id node_name () =
  Connection_context.use_current
    (get_block_trace_info_entries ?max_length ?offset ?height ?global_slot
       ?chain_length ?order deployment_id node_name)

let add_block_trace_checkpoint block_trace_id is_main source call_id checkpoint
    (module Db : Caqti_async.CONNECTION) =
  Db.exec Q.add_block_trace_checkpoint
    (block_trace_id, is_main, { source; call_id; checkpoint })

let add_block_trace_checkpoint block_trace_id is_main source call_id checkpoint
    =
  Connection_context.use_current
    (add_block_trace_checkpoint block_trace_id is_main source call_id checkpoint)

let get_block_trace_checkpoints ~main_trace block_trace_id
    (module Db : Caqti_async.CONNECTION) =
  Db.collect_list Q.select_block_trace_checkpoints (block_trace_id, main_trace)

let get_block_trace_checkpoints ~main_trace block_trace_id =
  Connection_context.use_current
    (get_block_trace_checkpoints ~main_trace block_trace_id)

let update_block_trace_block_id block_trace_id block_id
    (module Db : Caqti_async.CONNECTION) =
  Db.exec Q.update_block_trace_block_id (block_id, block_trace_id)

let update_block_trace_block_id block_trace_id block_id =
  Connection_context.use_current
    (update_block_trace_block_id block_trace_id block_id)

let set_value key node_name value (module Db : Caqti_async.CONNECTION) =
  Db.exec Q.set_value (key, node_name, value)

let set_value key node_name value = Connection_context.use_current (set_value key node_name value)

 
let get_current_deployment_id () (module Db : Caqti_async.CONNECTION) =
  Db.find_opt Q.get_current_deployment_id ()

let get_current_deployment_id () =
  Connection_context.use_current (get_current_deployment_id ())

let get_all_deployments_ids () (module Db : Caqti_async.CONNECTION) =
  Db.collect_list Q.get_deployments_ids ()
  
let get_all_deployments_ids () =
  Connection_context.use_current (get_all_deployments_ids ())

let get_nodes_names deployment_id (module Db : Caqti_async.CONNECTION) =
  Db.collect_list Q.get_nodes_names deployment_id

let get_nodes_names deployment_id =
  Connection_context.use_current ( get_nodes_names deployment_id )
  

let get_value key deployment_id node_name (module Db : Caqti_async.CONNECTION) =
  Db.find_opt Q.get_value (deployment_id, node_name, key)

let get_value key deployment_id node_name = Connection_context.use_current (get_value deployment_id node_name key)

module Testing = struct
  let report_error = function
    | Ok () ->
        Deferred.unit
    | Error err ->
        print_endline (Caqti_error.show err) ;
        exit 69

  let test_db () =
    let open Deferred.Result.Let_syntax in
    let trace =
      { Persisted_block_trace.source = `External
      ; deployment_id = 1
      ; blockchain_length = 11
      ; global_slot = 20
      ; started_at = 12345.0
      ; status = `Success
      ; total_time = 10.0
      ; metadata = `Assoc []
      }
    in
    let%bind block_trace_0_id = add_block_trace "test-1" trace "node-1" in
    let%bind block_trace_1_id = add_block_trace "test-2" trace "node-2" in
    printf "block trace #0 id=%d\n%!" block_trace_0_id ;
    printf "block trace #1 id=%d\n%!" block_trace_1_id ;
    let%bind () = update_block_trace_block_id block_trace_1_id "test-3" in
    let%bind result = get_block_traces "test-1" "node-1" 1 in
    let%bind () =
      ( match result with
      | (block_id, trace) :: _ ->
          printf "Found block_id=%d, trace:\n%s\n%!" block_id
            (Yojson.Safe.pretty_to_string
               (Persisted_block_trace.to_yojson trace) )
      | [] ->
          print_endline "not fund" ) ;
      Deferred.Result.return ()
    in
    let%bind entries = get_block_trace_info_entries 1 "node-1" () in
    printf "Trace entries count: %d\n%!" (List.length entries) ;
    List.iteri entries ~f:(fun i trace ->
        printf "Entry #%d:\n%s\n\n%!" i
          (Yojson.Safe.pretty_to_string
             (Block_tracing.Registry.trace_info_to_yojson trace) ) ) ;
    let%bind checkpoints =
      get_block_trace_checkpoints ~main_trace:true block_trace_0_id
    in
    printf "Checkpoint entries count: %d\n%!" (List.length checkpoints) ;
    let%bind () =
      add_block_trace_checkpoint block_trace_0_id true `Main 0
        (`Checkpoint ("Finish", 12375.0))
    in
    let%map checkpoints =
      get_block_trace_checkpoints ~main_trace:true block_trace_0_id
    in
    printf "Checkpoint entries count: %d\n%!" (List.length checkpoints) ;
    ()

  let test_storage =
    Command.async ~summary:"Test storage"
      (let%map_open.Command dburi =
         flag "--dburi" ~aliases:[ "dburi" ]
           (optional_with_default "sqlite3::memory:" string)
           ~doc:"db uri"
       in
       printf "dburi: %s\n%!" dburi ;
       let dburi = Uri.of_string dburi in
       fun () ->
         let pool =
           match Caqti_async.connect_pool dburi with
           | Error err ->
               failwith (Caqti_error.show err)
           | Ok pool ->
               pool
         in
         Connection_context.Db.set `Sqlite pool ;
         test_db () >>= report_error )
end
