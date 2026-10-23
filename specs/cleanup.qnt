module cleanup {
  type State = {
    phase: str,
    owner: str,
    protected: bool,
    identity: int,
    contents: int,
    plannedIdentity: int,
    plannedContents: int,
    operation: str,
    allowed: bool
  }
  var state: State

  action init = state' = {
    phase: "empty", owner: "released", protected: false,
    identity: 0, contents: 0, plannedIdentity: 0, plannedContents: 0,
    operation: "init", allowed: false
  }

  val safe = state.owner == "released" and not(state.protected)
    and state.identity == state.plannedIdentity
    and state.contents == state.plannedContents

  action plan = all {
    state.phase == "empty",
    state' = state.with("phase", "planned")
      .with("plannedIdentity", state.identity)
      .with("plannedContents", state.contents)
      .with("operation", "plan").with("allowed", false)
  }
  action changeOwner = {
    nondet owner = Set("released", "active", "kept", "unclaimed").oneOf()
    all {
      state.phase != "deleted",
      state' = state.with("owner", owner).with("operation", "owner").with("allowed", false)
    }
  }
  action protect = all {
    state.phase != "deleted",
    state' = state.with("protected", not(state.protected)).with("operation", "protect").with("allowed", false)
  }
  action replace = all {
    state.phase != "deleted", state.identity == 0,
    state' = state.with("identity", 1).with("operation", "replace").with("allowed", false)
  }
  action modify = all {
    state.phase != "deleted", state.contents == 0,
    state' = state.with("contents", 1).with("operation", "modify").with("allowed", false)
  }
  action interrupt = all {
    state.phase == "planned",
    state' = state.with("phase", "empty").with("operation", "interrupt").with("allowed", false)
  }
  action apply = all {
    state.phase == "planned",
    state' = state.with("phase", if (safe) "deleted" else "planned")
      .with("operation", "apply").with("allowed", safe)
  }
  action idle = state' = state.with("operation", "idle").with("allowed", false)
  action step = any { plan, changeOwner, protect, replace, modify, interrupt, apply, idle }

  val deletionSafe = state.phase != "deleted" or safe
  val noCapabilityAfterInterruption = state.operation != "interrupt" or (state.phase == "empty" and not(state.allowed))
  val validState = Set("empty", "planned", "deleted").contains(state.phase)
    and Set("released", "active", "kept", "unclaimed").contains(state.owner)
    and Set(0, 1).contains(state.identity) and Set(0, 1).contains(state.contents)
  val safety = deletionSafe and noCapabilityAfterInterruption and validState

  run deletionWitness = init.then(plan).then(apply).expect(state.phase == "deleted")
  run staleWitness = init.then(plan).then(replace).then(apply).expect(state.phase == "planned")
  run interruptionWitness = init.then(plan).then(interrupt).expect(state.phase == "empty")
}
