//! Exhaustive arbitration matrix for the retained coordination simulation.
//!
//! Every combination of mode, human input, agent input and grant is checked
//! twice: against an authored policy table and against invariants stated
//! independently of `Engine::step` (hazards H1, H2, H4 and H5 in
//! docs/threat-model.md). Actor labels and grants are caller-supplied data,
//! not authenticated identity; these tests pin arbitration behavior only.
use mira::{
    Actor, Engine, Event, Grant, Mode, Move, Outcome, Position, Proposal, Reason, Scenario,
    demo_scenario,
};

/// Arbitration is evaluated at tick 1 so that both past and future proposals exist.
const NOW: u64 = 1;
const START: Position = Position { x: 0, y: 1 };
/// Distinct safe moves identify whose command executed.
const HUMAN_SAFE: Move = Move::East;
const AGENT_SAFE: Move = Move::South;
/// Leaves the grid from START.
const UNSAFE: Move = Move::West;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Input {
    Absent,
    CurrentSafe,
    CurrentUnsafe,
    Past,
    Future,
    /// A current, safe proposal submitted in this slot under the other actor's label.
    Mislabeled,
}

const INPUTS: [Input; 6] = [
    Input::Absent,
    Input::CurrentSafe,
    Input::CurrentUnsafe,
    Input::Past,
    Input::Future,
    Input::Mislabeled,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GrantCase {
    Absent,
    ExpiresNow,
    ValidNextTick,
    ValidUnbounded,
    HumanActor,
}

const GRANTS: [GrantCase; 5] = [
    GrantCase::Absent,
    GrantCase::ExpiresNow,
    GrantCase::ValidNextTick,
    GrantCase::ValidUnbounded,
    GrantCase::HumanActor,
];

const MODES: [Mode; 4] = [
    Mode::Manual,
    Mode::Advisory,
    Mode::Assisted,
    Mode::Delegated,
];

fn proposal(slot: Actor, input: Input, safe: Move) -> Option<Proposal> {
    let other = match slot {
        Actor::Human => Actor::Agent,
        Actor::Agent => Actor::Human,
    };
    let (actor, command, tick) = match input {
        Input::Absent => return None,
        Input::CurrentSafe => (slot, safe, NOW),
        Input::CurrentUnsafe => (slot, UNSAFE, NOW),
        Input::Past => (slot, safe, NOW - 1),
        Input::Future => (slot, safe, NOW + 1),
        Input::Mislabeled => (other, safe, NOW),
    };
    Some(Proposal {
        actor,
        command,
        tick,
    })
}

fn grant(case: GrantCase) -> Option<Grant> {
    let (actor, expires_at) = match case {
        GrantCase::Absent => return None,
        GrantCase::ExpiresNow => (Actor::Agent, NOW),
        GrantCase::ValidNextTick => (Actor::Agent, NOW + 1),
        GrantCase::ValidUnbounded => (Actor::Agent, u64::MAX),
        GrantCase::HumanActor => (Actor::Human, u64::MAX),
    };
    Some(Grant { actor, expires_at })
}

fn engine_at_now() -> Engine {
    let mut engine = Engine::new(demo_scenario()).unwrap();
    engine.step(Mode::Manual, None, None, None).unwrap();
    assert_eq!((engine.tick(), engine.position()), (NOW, START));
    engine
}

fn run(mode: Mode, human: Input, agent: Input, grant_case: GrantCase) -> (Engine, Event) {
    let mut engine = engine_at_now();
    let event = engine
        .step(
            mode,
            proposal(Actor::Human, human, HUMAN_SAFE),
            proposal(Actor::Agent, agent, AGENT_SAFE),
            grant(grant_case),
        )
        .unwrap();
    (engine, event)
}

fn stale(input: Input) -> bool {
    matches!(input, Input::Past | Input::Future)
}

/// Authored policy table. A mislabeled proposal counts as absent, never as stale.
fn expected(mode: Mode, human: Input, agent: Input, grant_case: GrantCase) -> (Move, Reason) {
    let unattended = if stale(human) {
        Reason::RejectedStale
    } else {
        Reason::NoProposal
    };
    let valid_grant = matches!(
        grant_case,
        GrantCase::ValidNextTick | GrantCase::ValidUnbounded
    );
    match (mode, human) {
        (Mode::Manual, Input::CurrentSafe) => (HUMAN_SAFE, Reason::HumanControl),
        (Mode::Advisory, Input::CurrentSafe) => (HUMAN_SAFE, Reason::AdviceOnly),
        (Mode::Assisted, Input::CurrentSafe) => (HUMAN_SAFE, Reason::HumanControl),
        (Mode::Delegated, Input::CurrentSafe) => (HUMAN_SAFE, Reason::HumanOverride),
        (Mode::Assisted, Input::CurrentUnsafe) if agent == Input::CurrentSafe => {
            (AGENT_SAFE, Reason::SafeAssistance)
        }
        (_, Input::CurrentUnsafe) => (Move::Stay, Reason::RejectedUnsafe),
        (Mode::Delegated, _) if valid_grant => match agent {
            Input::CurrentSafe => (AGENT_SAFE, Reason::AgentDelegation),
            Input::CurrentUnsafe => (Move::Stay, Reason::RejectedUnsafe),
            Input::Past | Input::Future => (Move::Stay, Reason::RejectedStale),
            Input::Absent | Input::Mislabeled => (Move::Stay, Reason::NoProposal),
        },
        (Mode::Delegated, _) => (Move::Stay, Reason::NoValidGrant),
        _ => (Move::Stay, unattended),
    }
}

fn each_case(mut check: impl FnMut(Mode, Input, Input, GrantCase)) {
    for mode in MODES {
        for human in INPUTS {
            for agent in INPUTS {
                for grant_case in GRANTS {
                    check(mode, human, agent, grant_case);
                }
            }
        }
    }
}

#[test]
fn matrix_matches_authored_policy_and_covers_every_reason() {
    let mut seen = Vec::new();
    let mut cases = 0;
    each_case(|mode, human, agent, grant_case| {
        let case = format!("{mode:?} human={human:?} agent={agent:?} grant={grant_case:?}");
        let (engine, event) = run(mode, human, agent, grant_case);
        let (command, reason) = expected(mode, human, agent, grant_case);
        assert_eq!(event.decision.command, command, "{case}");
        assert_eq!(event.decision.reason, reason, "{case}");
        // Recorded transition, tick and history agree with the decision.
        let delta = command.delta();
        let after = Position {
            x: START.x + delta.x,
            y: START.y + delta.y,
        };
        assert_eq!((event.tick, event.before, event.after), (NOW, START, after));
        assert_eq!((engine.tick(), engine.position()), (NOW + 1, after));
        assert_eq!(engine.history().last(), Some(&event), "{case}");
        assert_eq!(event.outcome, Outcome::Running, "{case}");
        if !seen.contains(&reason) {
            seen.push(reason);
        }
        cases += 1;
    });
    assert_eq!(cases, 4 * 6 * 6 * 5);
    for reason in [
        Reason::HumanControl,
        Reason::AdviceOnly,
        Reason::SafeAssistance,
        Reason::AgentDelegation,
        Reason::HumanOverride,
        Reason::NoValidGrant,
        Reason::RejectedStale,
        Reason::RejectedUnsafe,
        Reason::NoProposal,
    ] {
        assert!(seen.contains(&reason), "matrix never produced {reason:?}");
    }
}

#[test]
fn current_safe_human_proposal_always_takes_precedence() {
    // H1: no agent input or grant can displace a current, safe human proposal.
    each_case(|mode, human, agent, grant_case| {
        if human == Input::CurrentSafe {
            let (_, event) = run(mode, human, agent, grant_case);
            assert_eq!(event.decision.command, HUMAN_SAFE, "{mode:?} {agent:?}");
        }
    });
}

#[test]
fn only_current_safe_correctly_labeled_proposals_move_the_state() {
    // H2: stale, unsafe and mislabeled proposals never change state.
    each_case(|mode, human, agent, grant_case| {
        let (_, event) = run(mode, human, agent, grant_case);
        match event.decision.command {
            Move::Stay => assert_eq!(event.after, START),
            HUMAN_SAFE => assert_eq!(human, Input::CurrentSafe),
            AGENT_SAFE => assert_eq!(agent, Input::CurrentSafe),
            other => panic!("unsubmitted command executed: {other:?}"),
        }
    });
}

#[test]
fn agent_commands_execute_only_through_assistance_or_valid_delegation() {
    // H4/H5: without a valid grant, an agent acts only as a recorded assisted
    // substitution for an unsafe current human proposal.
    each_case(|mode, human, agent, grant_case| {
        let (_, event) = run(mode, human, agent, grant_case);
        if event.decision.command == AGENT_SAFE {
            let valid_grant = matches!(
                grant_case,
                GrantCase::ValidNextTick | GrantCase::ValidUnbounded
            );
            let assisted = mode == Mode::Assisted && human == Input::CurrentUnsafe;
            let delegated = mode == Mode::Delegated && valid_grant && human != Input::CurrentSafe;
            assert!(assisted || delegated, "{mode:?} {human:?} {grant_case:?}");
            let reason = if assisted {
                Reason::SafeAssistance
            } else {
                Reason::AgentDelegation
            };
            assert_eq!(event.decision.reason, reason);
        }
    });
}

#[test]
fn mislabeled_proposals_are_equivalent_to_absent_ones() {
    // A label naming the other actor neither acts nor counts as a stale proposal.
    each_case(|mode, human, agent, grant_case| {
        let (_, actual) = run(mode, human, agent, grant_case);
        let human = if human == Input::Mislabeled {
            Input::Absent
        } else {
            human
        };
        let agent = if agent == Input::Mislabeled {
            Input::Absent
        } else {
            agent
        };
        let (_, reference) = run(mode, human, agent, grant_case);
        assert_eq!(actual, reference, "{mode:?} {human:?} {agent:?}");
    });
}

#[test]
fn grants_and_agent_input_have_no_effect_where_the_mode_excludes_them() {
    each_case(|mode, human, agent, grant_case| {
        let (_, actual) = run(mode, human, agent, grant_case);
        if mode != Mode::Delegated {
            let (_, reference) = run(mode, human, agent, GrantCase::Absent);
            assert_eq!(actual, reference, "grant changed {mode:?}");
        }
        if matches!(mode, Mode::Manual | Mode::Advisory) {
            let (_, reference) = run(mode, human, Input::Absent, grant_case);
            assert_eq!(actual, reference, "agent changed {mode:?}");
        }
    });
}

#[test]
fn identical_inputs_produce_identical_events() {
    each_case(|mode, human, agent, grant_case| {
        assert_eq!(
            run(mode, human, agent, grant_case).1,
            run(mode, human, agent, grant_case).1
        );
    });
}

#[test]
fn goal_on_the_final_tick_takes_precedence_over_timeout_and_is_terminal() {
    // H3: exactly one terminal outcome, and a terminal engine rejects further steps.
    let scenario = Scenario {
        width: 3,
        height: 1,
        start: Position { x: 0, y: 0 },
        goal: Position { x: 1, y: 0 },
        obstacles: Vec::new(),
        max_ticks: 1,
    };
    let east = Proposal {
        actor: Actor::Human,
        command: Move::East,
        tick: 0,
    };
    let mut engine = Engine::new(scenario.clone()).unwrap();
    let event = engine.step(Mode::Manual, Some(east), None, None).unwrap();
    assert_eq!(event.outcome, Outcome::GoalReached);
    assert_eq!(engine.outcome(), Outcome::GoalReached);
    let frozen = (engine.position(), engine.tick(), engine.history().to_vec());
    let next = Proposal { tick: 1, ..east };
    assert!(engine.step(Mode::Manual, Some(next), None, None).is_err());
    assert_eq!(
        (engine.position(), engine.tick(), engine.history().to_vec()),
        frozen
    );

    let mut engine = Engine::new(scenario).unwrap();
    let event = engine.step(Mode::Manual, None, None, None).unwrap();
    assert_eq!(event.outcome, Outcome::TimedOut);
    assert!(engine.step(Mode::Manual, None, None, None).is_err());
}
