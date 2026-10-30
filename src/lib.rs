//! MIRA: deterministic offline human-autonomy coordination.
//! This is an experimental simulator, not an authenticated or safety-certified controller.

pub mod evidence;
pub mod evidence_json;
pub mod experiment;
pub mod host_extra;
pub mod linux;
pub mod packages;
pub mod systemd;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Position {
    pub x: i32,
    pub y: i32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Move {
    Stay,
    North,
    East,
    South,
    West,
}
impl Move {
    pub const fn delta(self) -> Position {
        match self {
            Self::Stay => Position { x: 0, y: 0 },
            Self::North => Position { x: 0, y: -1 },
            Self::East => Position { x: 1, y: 0 },
            Self::South => Position { x: 0, y: 1 },
            Self::West => Position { x: -1, y: 0 },
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Actor {
    Human,
    Agent,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Manual,
    Advisory,
    Assisted,
    Delegated,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proposal {
    pub actor: Actor,
    pub command: Move,
    pub tick: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    pub actor: Actor,
    pub expires_at: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    HumanControl,
    AdviceOnly,
    SafeAssistance,
    AgentDelegation,
    HumanOverride,
    NoValidGrant,
    RejectedStale,
    RejectedUnsafe,
    NoProposal,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    pub command: Move,
    pub reason: Reason,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Running,
    GoalReached,
    TimedOut,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub tick: u64,
    pub before: Position,
    pub after: Position,
    pub decision: Decision,
    pub outcome: Outcome,
}
#[derive(Clone, Debug)]
pub struct Scenario {
    pub width: i32,
    pub height: i32,
    pub start: Position,
    pub goal: Position,
    pub obstacles: Vec<Position>,
    pub max_ticks: u64,
}
impl Scenario {
    fn inside(&self, p: Position) -> bool {
        p.x >= 0 && p.y >= 0 && p.x < self.width && p.y < self.height
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.width <= 0
            || self.height <= 0
            || self.max_ticks == 0
            || !self.inside(self.start)
            || !self.inside(self.goal)
            || self
                .obstacles
                .iter()
                .any(|&p| !self.inside(p) || p == self.start || p == self.goal)
        {
            return Err("invalid scenario");
        }
        Ok(())
    }
    fn blocked(&self, p: Position) -> bool {
        !self.inside(p) || self.obstacles.contains(&p)
    }
}
pub struct Engine {
    scenario: Scenario,
    position: Position,
    tick: u64,
    outcome: Outcome,
    history: Vec<Event>,
}
impl Engine {
    pub fn new(scenario: Scenario) -> Result<Self, &'static str> {
        scenario.validate()?;
        let position = scenario.start;
        let outcome = if position == scenario.goal {
            Outcome::GoalReached
        } else {
            Outcome::Running
        };
        Ok(Self {
            scenario,
            position,
            tick: 0,
            outcome,
            history: Vec::new(),
        })
    }
    pub const fn position(&self) -> Position {
        self.position
    }
    pub const fn tick(&self) -> u64 {
        self.tick
    }
    pub const fn outcome(&self) -> Outcome {
        self.outcome
    }
    pub fn history(&self) -> &[Event] {
        &self.history
    }
    pub fn step(
        &mut self,
        mode: Mode,
        human: Option<Proposal>,
        agent: Option<Proposal>,
        grant: Option<Grant>,
    ) -> Result<Event, &'static str> {
        if self.outcome != Outcome::Running {
            return Err("simulation finished");
        }
        let now = self.tick;
        let human = human.filter(|p| p.actor == Actor::Human);
        let agent = agent.filter(|p| p.actor == Actor::Agent);
        let h = human.filter(|p| p.tick == now);
        let a = agent.filter(|p| p.tick == now);
        let valid_grant = grant.is_some_and(|g| g.actor == Actor::Agent && now < g.expires_at);
        let safe = |m: Move| {
            let d = m.delta();
            self.position
                .x
                .checked_add(d.x)
                .zip(self.position.y.checked_add(d.y))
                .is_some_and(|(x, y)| !self.scenario.blocked(Position { x, y }))
        };
        let decision = match mode {
            Mode::Manual | Mode::Advisory => match h {
                Some(p) if safe(p.command) => Decision {
                    command: p.command,
                    reason: if mode == Mode::Manual {
                        Reason::HumanControl
                    } else {
                        Reason::AdviceOnly
                    },
                },
                Some(_) => Decision {
                    command: Move::Stay,
                    reason: Reason::RejectedUnsafe,
                },
                None => Decision {
                    command: Move::Stay,
                    reason: if human.is_some() {
                        Reason::RejectedStale
                    } else {
                        Reason::NoProposal
                    },
                },
            },
            Mode::Assisted => match h {
                Some(p) if safe(p.command) => Decision {
                    command: p.command,
                    reason: Reason::HumanControl,
                },
                Some(_) => match a {
                    Some(q) if safe(q.command) => Decision {
                        command: q.command,
                        reason: Reason::SafeAssistance,
                    },
                    _ => Decision {
                        command: Move::Stay,
                        reason: Reason::RejectedUnsafe,
                    },
                },
                None => Decision {
                    command: Move::Stay,
                    reason: if human.is_some() {
                        Reason::RejectedStale
                    } else {
                        Reason::NoProposal
                    },
                },
            },
            Mode::Delegated => match h {
                Some(p) if safe(p.command) => Decision {
                    command: p.command,
                    reason: Reason::HumanOverride,
                },
                Some(_) => Decision {
                    command: Move::Stay,
                    reason: Reason::RejectedUnsafe,
                },
                None if valid_grant => match a {
                    Some(p) if safe(p.command) => Decision {
                        command: p.command,
                        reason: Reason::AgentDelegation,
                    },
                    Some(_) => Decision {
                        command: Move::Stay,
                        reason: Reason::RejectedUnsafe,
                    },
                    None => Decision {
                        command: Move::Stay,
                        reason: if agent.is_some() {
                            Reason::RejectedStale
                        } else {
                            Reason::NoProposal
                        },
                    },
                },
                None => Decision {
                    command: Move::Stay,
                    reason: Reason::NoValidGrant,
                },
            },
        };
        let before = self.position;
        let d = decision.command.delta();
        self.position = Position {
            x: before.x + d.x,
            y: before.y + d.y,
        };
        self.tick += 1;
        if self.position == self.scenario.goal {
            self.outcome = Outcome::GoalReached;
        } else if self.tick >= self.scenario.max_ticks {
            self.outcome = Outcome::TimedOut;
        }
        let event = Event {
            tick: now,
            before,
            after: self.position,
            decision,
            outcome: self.outcome,
        };
        self.history.push(event.clone());
        Ok(event)
    }
}
pub fn demo_scenario() -> Scenario {
    Scenario {
        width: 6,
        height: 4,
        start: Position { x: 0, y: 1 },
        goal: Position { x: 4, y: 1 },
        obstacles: vec![Position { x: 2, y: 1 }],
        max_ticks: 20,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn p(actor: Actor, command: Move, tick: u64) -> Option<Proposal> {
        Some(Proposal {
            actor,
            command,
            tick,
        })
    }
    #[test]
    fn invalid_scenario() {
        let mut s = demo_scenario();
        s.obstacles.push(s.goal);
        assert!(Engine::new(s).is_err());
    }
    #[test]
    fn unsafe_movement() {
        let mut e = Engine::new(demo_scenario()).unwrap();
        e.step(Mode::Manual, p(Actor::Human, Move::East, 0), None, None)
            .unwrap();
        assert_eq!(
            e.step(Mode::Manual, p(Actor::Human, Move::East, 1), None, None)
                .unwrap()
                .decision
                .reason,
            Reason::RejectedUnsafe
        );
    }
    #[test]
    fn agent_advice_does_not_execute() {
        let mut e = Engine::new(demo_scenario()).unwrap();
        e.step(Mode::Advisory, None, p(Actor::Agent, Move::East, 0), None)
            .unwrap();
        assert_eq!(e.position(), Position { x: 0, y: 1 });
    }
    #[test]
    fn expired_grant_does_not_execute() {
        let mut e = Engine::new(demo_scenario()).unwrap();
        assert_eq!(
            e.step(
                Mode::Delegated,
                None,
                p(Actor::Agent, Move::East, 0),
                Some(Grant {
                    actor: Actor::Agent,
                    expires_at: 0
                })
            )
            .unwrap()
            .decision
            .reason,
            Reason::NoValidGrant
        );
    }
    #[test]
    fn override_works() {
        let mut e = Engine::new(demo_scenario()).unwrap();
        assert_eq!(
            e.step(
                Mode::Delegated,
                p(Actor::Human, Move::North, 0),
                p(Actor::Agent, Move::East, 0),
                Some(Grant {
                    actor: Actor::Agent,
                    expires_at: 3
                })
            )
            .unwrap()
            .decision
            .reason,
            Reason::HumanOverride
        );
    }
    #[test]
    fn replay_is_deterministic() {
        fn run() -> Vec<Event> {
            let mut e = Engine::new(demo_scenario()).unwrap();
            for t in 0..4 {
                e.step(Mode::Manual, p(Actor::Human, Move::East, t), None, None)
                    .unwrap();
            }
            e.history().to_vec()
        }
        assert_eq!(run(), run());
    }
}
