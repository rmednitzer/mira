//! Versioned experiment inputs and replay verification.
//!
//! This layer records caller-supplied requests and decisions. It does not
//! authenticate the actor field or make delegation tamper-resistant.
use crate::{Engine, Event, Grant, Mode, Outcome, Proposal, Scenario};

/// Semantic format version of the in-memory experiment contract.
pub const PROTOCOL_VERSION: u32 = 1;

/// An input frame is evaluated at the engine's current tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    pub mode: Mode,
    pub human: Option<Proposal>,
    pub agent: Option<Proposal>,
    pub grant: Option<Grant>,
}

/// A recorded input and the exact observed transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub input: Frame,
    pub event: Event,
}

/// A single run bound to a scenario and an explicit protocol version.
#[derive(Clone, Debug)]
pub struct Trace {
    pub version: u32,
    pub scenario: Scenario,
    pub records: Vec<Record>,
    pub final_outcome: Outcome,
}

/// Deterministic execution with recorded inputs. The simulation engine is the
/// sole executor; participants only provide proposals.
pub fn run(scenario: Scenario, frames: &[Frame]) -> Result<Trace, &'static str> {
    let mut engine = Engine::new(scenario.clone())?;
    let mut records = Vec::with_capacity(frames.len().min(1024));
    for frame in frames {
        let event = engine.step(frame.mode, frame.human, frame.agent, frame.grant)?;
        records.push(Record {
            input: *frame,
            event,
        });
    }
    Ok(Trace {
        version: PROTOCOL_VERSION,
        scenario,
        records,
        final_outcome: engine.outcome(),
    })
}

/// Verifies all recorded decisions and state transitions by re-executing the
/// same inputs. This is not cryptographic integrity verification: someone
/// controlling both the inputs and trace can replace both consistently.
pub fn verify(trace: &Trace) -> Result<(), &'static str> {
    if trace.version != PROTOCOL_VERSION {
        return Err("unsupported protocol version");
    }
    let mut engine = Engine::new(trace.scenario.clone())?;
    for record in &trace.records {
        let actual = engine.step(
            record.input.mode,
            record.input.human,
            record.input.agent,
            record.input.grant,
        )?;
        if actual != record.event {
            return Err("event mismatch");
        }
    }
    if engine.outcome() != trace.final_outcome {
        return Err("outcome mismatch");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Actor, Move, Position, Reason, demo_scenario};

    fn human(command: Move, tick: u64) -> Frame {
        Frame {
            mode: Mode::Manual,
            human: Some(Proposal {
                actor: Actor::Human,
                command,
                tick,
            }),
            agent: None,
            grant: None,
        }
    }

    #[test]
    fn validates_identical_replay() {
        let trace = run(
            demo_scenario(),
            &[human(Move::East, 0), human(Move::East, 1)],
        )
        .expect("valid run");
        assert_eq!(trace.records.len(), 2);
        assert_eq!(
            trace.records[1].event.decision.reason,
            Reason::RejectedUnsafe
        );
        assert!(verify(&trace).is_ok());
    }

    #[test]
    fn detects_modified_transition() {
        let mut trace = run(demo_scenario(), &[human(Move::East, 0)]).expect("valid run");
        trace.records[0].event.after = Position { x: 5, y: 3 };
        assert_eq!(verify(&trace), Err("event mismatch"));
    }

    #[test]
    fn detects_changed_outcome() {
        let mut trace = run(demo_scenario(), &[human(Move::Stay, 0)]).expect("valid run");
        trace.final_outcome = Outcome::GoalReached;
        assert_eq!(verify(&trace), Err("outcome mismatch"));
    }

    #[test]
    fn rejects_unknown_versions() {
        let mut trace = run(demo_scenario(), &[]).expect("valid run");
        trace.version += 1;
        assert_eq!(verify(&trace), Err("unsupported protocol version"));
    }

    #[test]
    fn disallows_steps_after_terminal_state() {
        let mut scenario = demo_scenario();
        scenario.max_ticks = 1;
        assert!(run(scenario, &[human(Move::Stay, 0), human(Move::Stay, 1)]).is_err());
    }

    #[test]
    fn records_explicit_delegation_rejection() {
        let frame = Frame {
            mode: Mode::Delegated,
            human: None,
            agent: Some(Proposal {
                actor: Actor::Agent,
                command: Move::East,
                tick: 0,
            }),
            grant: None,
        };
        let trace = run(demo_scenario(), &[frame]).expect("valid run");
        assert_eq!(trace.records[0].event.decision.reason, Reason::NoValidGrant);
        assert!(verify(&trace).is_ok());
    }
}
