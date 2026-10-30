use mira::{demo_scenario, Actor, Engine, Mode, Move, Outcome, Proposal};
fn main() {
    let mut engine = Engine::new(demo_scenario()).expect("valid demo");
    for tick in 0..8 {
        if engine.outcome() != Outcome::Running { break; }
        let command = Proposal { actor: Actor::Human, command: Move::East, tick };
        let event = engine.step(Mode::Manual, Some(command), None, None).expect("step");
        println!("{event:?}");
    }
}
