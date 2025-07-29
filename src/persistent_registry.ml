open Core
open Async

let node_name =
  match Sys.getenv "MINA_NODE_NAME" with
  | None ->
      Log.Global.error "[WARN] no MINA_NODE_NAME specified, using \"unknown\"" ;
      "unknown"
  | Some name ->
      name


let block_id_trace_id_mapping = String.Table.create ()

let block_trace_status = Int.Table.create ()

let block_trace_id block_id =
  String.Table.find block_id_trace_id_mapping block_id

let add_block_trace ~source block_id =
  let open Deferred.Result.Let_syntax in
  let%bind current_deployment_id =
    Store.get_current_deployment_id () |> Deferred.Result.map ~f:(fun option -> Option.value_exn option ~message:"Deployment table is empty!")
  in
  let trace =
    Store.Persisted_block_trace.from_block_trace @@ Block_trace.empty source current_deployment_id
  in
  let%map block_trace_id = Store.add_block_trace block_id trace node_name in
  ignore
  @@ String.Table.add ~key:block_id ~data:block_trace_id
       block_id_trace_id_mapping ;
  ignore
  @@ Int.Table.add ~key:block_trace_id ~data:trace.status block_trace_status ;
  block_trace_id

let get_or_add_block_trace ~source block_id =
  match String.Table.find block_id_trace_id_mapping block_id with
  | None ->
      Log.Global.debug "adding block trace id %s" block_id;
      add_block_trace ~source block_id
  | Some id ->
      Log.Global.debug "returning existing block trace id %s" block_id;
      return (Ok id)

let push_checkpoint block_trace_id ~is_main ~source ?(call_id = 0) ~name
    ~timestamp () =
  Store.add_block_trace_checkpoint block_trace_id is_main source call_id
    (`Checkpoint (name, timestamp))

let push_control block_trace_id ~is_main ~source ?(call_id = 0) ~name ~metadata
    () =
  Log.Global.debug "adding block trace checkpoint for trace id %d" block_trace_id;
  Store.add_block_trace_checkpoint block_trace_id is_main source call_id
    (`Control (name, metadata))

let push_block_metadata block_trace_id ~metadata =
  let open Deferred.Result.Let_syntax in
  let%bind _, trace = Store.get_block_trace_by_id block_trace_id in
  let blockchain_length =
    Option.value ~default:trace.blockchain_length
      (Block_trace.extract_blockchain_length metadata)
  in
  let global_slot =
    Option.value ~default:trace.global_slot
      (Block_trace.extract_global_slot metadata)
  in
  let trace =
    { trace with
      blockchain_length
    ; global_slot
    ; metadata = Yojson.Safe.Util.combine trace.metadata (`Assoc metadata)
    }
  in
  Store.update_block_trace block_trace_id trace

let set_produced_block_state_hash block_trace_id state_hash =
  ignore
  @@ String.Table.add block_id_trace_id_mapping ~key:state_hash
       ~data:block_trace_id ;
  Store.update_block_trace_block_id block_trace_id state_hash

let get_deployment_id_or_default (deployment_id : int option) = 
  let open Deferred.Result.Let_syntax in
  let%bind deployment_id =
    match deployment_id with
    | Some id ->
        return id
    | None ->
        Store.get_current_deployment_id () |> Deferred.Result.map ~f:(fun opt -> Option.value_exn ~message:"Deployment table is empty!" opt )
  in
    return deployment_id
  
let get_distributions (deployment_id : int option) (node_name : string ) =
  let open Deferred.Result.Let_syntax in
  let%bind deployment_id = get_deployment_id_or_default deployment_id in
  let%map distributions = Store.get_value "checkpoint_distributions" deployment_id node_name in
  match distributions with
  | None ->
      Hashtbl.create (module Block_checkpoint)
  | Some json ->
      let ys = Yojson.Safe.from_string json in
      Result.ok_or_failwith ([%of_yojson: Block_tracing.Distributions.store] ys)

let save_distributions distributions =
  Store.set_value "checkpoint_distributions"
    ( Yojson.Safe.to_string
    @@ [%to_yojson: Block_tracing.Distributions.store] distributions )

let update_distributions deployment_id (trace : Block_structured_trace.t) =
  let open Deferred.Result.Let_syntax in
  let%bind distributions = get_distributions deployment_id node_name in
  List.iter trace.sections ~f:(fun section ->
      List.iter section.checkpoints
        ~f:(Block_tracing.Distributions.integrate_entry ~store:distributions) ) ;
  save_distributions distributions node_name

let get_current_deployment_id () =
  Store.get_current_deployment_id () |> Deferred.Result.map ~f:(fun opt ->
      Option.value_exn ~message:"Deployment table is empty!" opt
    )
  

let handle_status_change block_trace_id status =
  let open Deferred.Result.Let_syntax in
  match (status, Int.Table.find block_trace_status block_trace_id) with
  | _, Some `Success ->
      return ()
  | status, Some old_status
    when not @@ Block_trace.equal_status old_status status -> (
      let%bind _block_id, trace = Store.get_block_trace_by_id block_trace_id in
      let%bind checkpoints =
        Store.get_block_trace_checkpoints ~main_trace:true block_trace_id
      in
      let timestamps =
        checkpoints
        |> List.filter_map ~f:(function
             | { source = `Main; checkpoint = `Checkpoint (_, t); call_id = _ }
               ->
                 Some t
             | _ ->
                 None )
      in
      let first_checkpoint =
        List.find_map
          ~f:(function
            | { checkpoint = `Checkpoint (name, _); _ } -> Some name | _ -> None
            )
          checkpoints
      in
      match first_checkpoint with
      | None ->
          Log.Global.error
            "[WARN] status change issued for a trace with no checkpoints: id=%d"
            block_trace_id ;
          return ()
      | Some first_checkpoint ->
          let source = Block_tracing.compute_source first_checkpoint in
          let started_at =
            Option.value_exn @@ List.min_elt ~compare:Float.compare timestamps
          in
          let completed_at =
            Option.value_exn @@ List.max_elt ~compare:Float.compare timestamps
          in
          let total_time = completed_at -. started_at in
          let trace = { trace with status; started_at; total_time; source } in
          let%bind () = Store.update_block_trace block_trace_id trace in
          ignore
          @@ Int.Table.add block_trace_status ~key:block_trace_id ~data:status ;
          let%bind () =
            if Block_trace.equal_status status `Success then
              let%bind current_deployment_id =
                Store.get_current_deployment_id ()
                |> Deferred.Result.map ~f:(fun opt -> Option.value_exn opt ~message:"Deployment table is empty!")
              in
              let trace =
                Store.Persisted_block_trace.to_block_trace ~checkpoints ~default_deployment_id:current_deployment_id trace
              in
              let deployment_id = trace.deployment_id in
              let trace = Block_structured_trace.of_flat_trace trace in
              update_distributions (Some deployment_id) trace
            else return ()
          in
          return () )
  | _ ->
      return ()

let get_block_trace_checkpoints block_trace_id =
  Store.get_block_trace_checkpoints ~main_trace:true block_trace_id

let get_block_trace_other_checkpoints block_trace_id =
  Store.get_block_trace_checkpoints ~main_trace:false block_trace_id

let get_block_traces node_name block_id deployment_id  = 
  let open Deferred.Result.Let_syntax in
  let%bind deployment_id = get_deployment_id_or_default deployment_id in
  Store.get_block_traces block_id node_name deployment_id 

let get_all_block_traces ?max_length ?offset ?height ?global_slot ?chain_length
    ?order ?deployment_id node_name () =
  let open Deferred.Result.Let_syntax in
  let%bind deployment_id = get_deployment_id_or_default deployment_id in
  Log.Global.info "Fetching block traces with deployment_id: %d" deployment_id ;
  Store.get_block_trace_info_entries ?max_length ?offset ?height ?global_slot
    ?chain_length ?order deployment_id node_name ()

let get_all_deployments_ids () = Store.get_all_deployments_ids ()

let get_nodes_names ?deployment_id () =
  let open Deferred.Result.Let_syntax in
  let%bind deployment_id = get_deployment_id_or_default deployment_id in
  Store.get_nodes_names deployment_id


let only_main_checkpoints =
  List.filter_map ~f:(function
    | { Store.source = `Main
      ; checkpoint = `Checkpoint (name, timestamp)
      ; call_id = _
      } ->
        Some (name, timestamp)
    | _ ->
        None )

let nearest_trace ~prev_checkpoint ~timestamp block_trace_id =
  let open Deferred.Result.Let_syntax in
  let%bind checkpoints = get_block_trace_checkpoints block_trace_id in
  let checkpoints = only_main_checkpoints checkpoints in
  let%bind other_checkpoints =
    get_block_trace_other_checkpoints block_trace_id
  in
  let other_checkpoints = only_main_checkpoints other_checkpoints in
  let left =
    List.find checkpoints ~f:(fun (checkpoint, started_at) ->
        Float.(started_at <= timestamp)
        && String.equal checkpoint prev_checkpoint )
  in
  let right =
    List.find other_checkpoints ~f:(fun (checkpoint, started_at) ->
        Float.(started_at <= timestamp)
        && String.equal checkpoint prev_checkpoint )
  in
  return
  @@
  match (left, right) with
  | None, None ->
      `Main
  | Some _, None ->
      `Main
  | None, Some _ ->
      `Other
  | Some (_, lstarted_at), Some (_, rstarted_at) ->
      if Float.(lstarted_at > rstarted_at) then `Main else `Other
